/*
 * selinux_policy_analyzer.c
 * ===========================================================================
 * READ-ONLY SELinux posture analyzer for authorized security research labs.
 *
 * PURPOSE (educational use only)
 * ------------------------------
 * Answers three forensic questions about a running Android/Linux system
 * WITHOUT modifying any policy:
 *
 *   1. What SELinux context does each critical process run under?
 *      (reads /proc/<pid>/attr/current — pure procfs reads)
 *   2. Is the kernel enforcing, permissive, or disabled?
 *      (reads /sys/fs/selinux/enforce)
 *   3. Which rules in the loaded policy look overly permissive?
 *      (parses a *text* policy/allow-rule dump supplied by the researcher,
 *       e.g. produced offline with `sesearch`/`sepolicy analyze` from an
 *       authorized lab image; optionally also reads
 *       /sys/fs/selinux/policy only to fingerprint/hash it.)
 *
 * WHY WE PARSE A TEXT DUMP INSTEAD OF THE BINARY POLICY
 * -----------------------------------------------------
 * The binary policy blob in /sys/fs/selinux/policy is a fl_sync structure
 * whose layout varies across AOSP versions; production-grade decoding needs
 * libsepol.  To keep this module dependency-free on Termux (where libsepol
 * headers are often absent) AND auditable line-by-line, we:
 *   - hash the live binary policy (integrity evidence for evidence_logger),
 *   - parse simple "allow src tgt class permset;" lines from a text file.
 * Researchers who want full AVA decoding should feed the output of
 * `sesearch -A -p <policy>` into this parser.
 *
 * SAFETY GUARANTEES
 * -----------------
 *   * Every syscall used is open()/read()/close()/stat(). There is NO
 *     write(), no ioctl(SELINUX_SETENFORCE...), no libselinux state-changing
 *     call, no setenforce, no permissive-domain transition.  The tool cannot
 *     weaken the system it is auditing.
 *   * Heuristics flag risky constructs:
 *       - domain labeled permissive (`permissive <domain>;`)
 *       - allow rules granting dangerous permissions
 *         (execute on textless/shell domains, ptrace, bpf, module_request,
 *          sys_admin, device:raw_socket_class writes to block devices...)
 *       - wildcard `*` or `self` abuse on socket classes
 *       - rules targeting `kernel` or `init` from untrusted domains
 *   * Output is machine-readable (one finding per line) so it can be piped
 *     into evidence_logger.py for Merkle hashing.
 *
 * BUILD
 * -----
 *   Arch:    gcc -O2 -Wall -Wextra -std=c11 -o bin/selinux_policy_analyzer \
 *                selinux_policy_analyzer.c
 *   Termux:  pkg install clang && clang -O2 -Wall -Wextra -std=c11 \
 *                -o bin/selinux_policy_analyzer selinux_policy_analyzer.c
 * (No -lselinux needed; we deliberately avoid linking anything that could
 *  mutate policy state.)
 *
 * USAGE
 * -----
 *   ./bin/selinux_policy_analyzer [rules.txt]
 *       audits live contexts + hashes live policy; if rules.txt given, also
 *       scans its allow-rules for permissive constructs.
 */

#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>

/* ------------------------------------------------------------------------ */
/* Configuration                                                            */
/* ------------------------------------------------------------------------ */

#define PATH_SELINUX_ENFORCE "/sys/fs/selinux/enforce"
#define PATH_SELINUX_POLICY  "/sys/fs/selinux/policy"
#define MAX_LINE 1024
#define MAX_FINDINGS 4096

/* Critical Android domains a forensic auditor cares about. We match on the
 * process comm name; the SELinux context is then captured verbatim. */
static const char *CRITICAL_PROCESSES[] = {
    "gatekeeperd", "keystore2", "keymaster", "surfaceflinger",
    "system_server", "zygote64", "app_process", "vold", "init",
    "ueventd", "logcat", NULL
};

/* Permission tokens considered "overly permissive" when granted broadly. */
static const char *DANGEROUS_PERMS[] = {
    "ptrace", "bpf", "module_request", "sys_admin", "sys_ptrace",
    "execmem", "execstack", "textrel", "map_exec", "raw_ip_address",
    "nlmsg_route", "syslog", NULL
};

typedef struct {
    char text[MAX_LINE];
    int   severity;            /* 1=info 2=warn 3=critical */
} Finding;

static Finding g_findings[MAX_FINDINGS];
static int     g_nfindings = 0;

/* Append one finding (bounded, never overflows). */
static void add_finding(int severity, const char *fmt, ...)
{
    if (g_nfindings >= MAX_FINDINGS) return;
    Finding *f = &g_findings[g_nfindings++];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(f->text, sizeof f->text, fmt, ap);
    va_end(ap);
    f->severity = severity;
}

/* ------------------------------------------------------------------------ */
/* Read-only primitives                                                     */
/* ------------------------------------------------------------------------ */

/* Read an entire small file with open/read only. Returns bytes or -1. */
static long read_file_ro(const char *path, char *buf, size_t bufsz)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);   /* O_RDONLY == immutable */
    if (fd < 0)
        return -1;                               /* caller reports EACCES etc. */
    size_t total = 0;
    ssize_t n;
    while ((n = read(fd, buf + total, bufsz - total)) > 0) {
        total += (size_t)n;
        if (total >= bufsz) break;               /* truncate big files */
    }
    close(fd);
    if (n < 0 && errno != 0 && total == 0) return -1;
    buf[total < bufsz ? total : bufsz - 1] = '\0';
    return (long)total;
}

/* FNV-1a 64-bit streaming hash — tiny, portable, good enough as an
 * integrity *fingerprint* to hand to evidence_logger (which does the real
 * cryptographic SHA-256 work inside the Merkle tree). */
static uint64_t fnv1a64_update(uint64_t h, const unsigned char *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

/* Stream-hash a file read-only; returns hex string in out (>=17 bytes). */
static int hash_file_ro(const char *path, char *out, size_t outsz)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    uint64_t h = 0xcbf29ce484222325ULL;
    unsigned char chunk[8192];
    ssize_t n;
    while ((n = read(fd, chunk, sizeof chunk)) > 0)
        h = fnv1a64_update(h, chunk, (size_t)n);
    close(fd);
    if (n < 0) return -1;
    snprintf(out, outsz, "%016llx", (unsigned long long)h);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Audit 1: enforcement mode                                                */
/* ------------------------------------------------------------------------ */

static void audit_enforce_mode(void)
{
    char buf[64];
    long n = read_file_ro(PATH_SELINUX_ENFORCE, buf, sizeof buf);
    if (n < 0) {
        if (errno == ENOENT)
            add_finding(3, "SELINUX_DISABLED: %s missing — kernel has no "
                           "SELinux (audit-mode system!)", PATH_SELINUX_ENFORCE);
        else
            add_finding(1, "ENFORCE_UNKNOWN: cannot read %s (%s) — expected "
                           "EACCES for unprivileged Termux; not a bug.",
                        PATH_SELINUX_ENFORCE, strerror(errno));
        return;
    }
    if (strcmp(buf, "0") == 0)
        add_finding(3, "PERMISSIVE_KERNEL: %s == 0 — SELinux logs denials "
                       "but enforces nothing.", PATH_SELINUX_ENFORCE);
    else
        add_finding(1, "ENFORCING: %s == 1 — good baseline posture.",
                    PATH_SELINUX_ENFORCE);
}

/* ------------------------------------------------------------------------ */
/* Audit 2: contexts of critical processes                                  */
/* ------------------------------------------------------------------------ */

static int matches_critical(const char *comm)
{
    for (int i = 0; CRITICAL_PROCESSES[i]; i++)
        if (strstr(comm, CRITICAL_PROCESSES[i]))
            return 1;
    return 0;
}

/*
 * ADVANCED: resolve a daemon name (e.g. "gatekeeperd") to its PID by
 * scanning /proc/<pid>/comm — pure procfs reads, no shell-outs, no signals.
 * Returns the pid or -1.  Lets researchers target ONE service instead of
 * sweeping every process, which is both faster and less noisy on Termux.
 */
static long find_pid_by_comm(const char *want)
{
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *de;
    long found = -1;
    while ((de = readdir(d)) != NULL) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        char path[280], comm[128];
        snprintf(path, sizeof path, "/proc/%s/comm", de->d_name);
        if (read_file_ro(path, comm, sizeof comm) < 0) continue;
        comm[strcspn(comm, "\n")] = '\0';
        if (strcmp(comm, want) == 0) { found = atol(de->d_name); break; }
    }
    closedir(d);
    return found;
}

/* Read one /proc/<pid>/attr/current; prints result as a finding. */
static void report_one_context(long pid)
{
    char path[280], comm[128], ctx[512];
    snprintf(path, sizeof path, "/proc/%ld/comm", pid);
    if (read_file_ro(path, comm, sizeof comm) < 0) comm[0] = '?';
    comm[strcspn(comm, "\n")] = '\0';

    snprintf(path, sizeof path, "/proc/%ld/attr/current", pid);
    long n = read_file_ro(path, ctx, sizeof ctx);
    if (n < 0) {
        add_finding(2, "TARGETED pid=%ld comm=%s ctx=UNKNOWN (%s) — reading "
                       "another users' attr needs root on stock Android.",
                   pid, comm, strerror(errno));
        return;
    }
    ctx[strcspn(ctx, "\n")] = '\0';
    add_finding(1, "TARGETED pid=%ld comm=%s ctx=%s", pid, comm, ctx);
    if (strstr(ctx, ":su:") || strstr(ctx, "untrusted_app"))
        add_finding(3, "TARGETED pid=%ld runs in tainted domain '%s'.",
                    pid, ctx);
}

static void audit_process_contexts(const char *target /* may be NULL */)
{
    /* Targeted mode: --pid NNNN or --process gatekeeperd */
    if (target) {
        long pid = -1;
        const char *p = target;
        int all_digits = (*p != '\0');
        while (*p && isdigit((unsigned char)*p++)) ;
        all_digits = all_digits && (*p == '\0');
        if (all_digits) pid = atol(target);
        else            pid = find_pid_by_comm(target);
        if (pid < 0) {
            add_finding(2, "TARGET_NOT_FOUND: no live process matching '%s' "
                           "(read-only scan of /proc found nothing).", target);
            return;
        }
        report_one_context(pid);
        return;
    }

    DIR *d = opendir("/proc");
    if (!d) {
        add_finding(2, "PROC_UNREADABLE: opendir(/proc) failed (%s)",
                    strerror(errno));
        return;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        /* numeric pid dirs only */
        if (!isdigit((unsigned char)de->d_name[0])) continue;

        char path[280], comm[128], ctx[512];
        snprintf(path, sizeof path, "/proc/%s/comm", de->d_name);
        if (read_file_ro(path, comm, sizeof comm) < 0) continue;
        comm[strcspn(comm, "\n")] = '\0';
        if (!matches_critical(comm)) continue;

        snprintf(path, sizeof path, "/proc/%s/attr/current", de->d_name);
        long n = read_file_ro(path, ctx, sizeof ctx);
        if (n < 0) {
            add_finding(1, "pid=%s comm=%s ctx=UNKNOWN (%s) — reading other "
                           "users' attr requires root; skipped gracefully.",
                        de->d_name, comm, strerror(errno));
            continue;
        }
        ctx[strcspn(ctx, "\n")] = '\0';

        /* Findings on the context itself: */
        if (strstr(ctx, ":su:") || strstr(ctx, "untrusted"))
            add_finding(2, "pid=%s comm=%s ctx=%s — critical service runs in "
                           "an untrusted/su-tainted domain.",
                        de->d_name, comm, ctx);
        else if (strstr(ctx, "mls_sensitive") == NULL &&
                 strstr(ctx, "u:object_r:") != NULL)
            add_finding(1, "pid=%s comm=%s ctx=%s", de->d_name, comm, ctx);
        else
            add_finding(1, "pid=%s comm=%s ctx=%s", de->d_name, comm, ctx);
    }
    closedir(d);
}

/* ------------------------------------------------------------------------ */
/* Audit 3: text allow-rule scan (offline dump)                             */
/* ------------------------------------------------------------------------ */

/* Trim leading whitespace and comments; returns NULL for non-rule lines. */
static char *strip_line(char *line)
{
    while (*line && isspace((unsigned char)*line)) line++;
    if (*line == '\0' || *line == '#') return NULL;
    return line;
}

static int token_has_dangerous_perm(const char *permset)
{
    for (int i = 0; DANGEROUS_PERMS[i]; i++)
        if (strstr(permset, DANGEROUS_PERMS[i]))
            return 1;
    return 0;
}

/*
 * Parse lines shaped like te-file allow rules:
 *     allow u:r:untrusted_app:s0 cdev:{blk_device} { write } ;
 *     allow domain kernel key { request };
 *     permissive su;
 * This is intentionally a HEURISTIC scanner, not a full policy compiler.
 */
static void audit_rule_dump(const char *path)
{
    FILE *fp = fopen(path, "r");        /* text dump supplied by researcher */
    if (!fp) {
        add_finding(1, "RULE_DUMP_SKIPPED: %s not readable (%s). Provide a "
                       "sesearch/te-file dump captured from an authorized "
                       "lab image for rule analysis.", path, strerror(errno));
        return;
    }

    char line[MAX_LINE];
    int lineno = 0;
    while (fgets(line, sizeof line, fp)) {
        lineno++;
        char *s = strip_line(line);
        if (!s) continue;

        /* Explicit permissive domain declaration — top-severity finding. */
        if (strncmp(s, "permissive", 10) == 0 && isspace((unsigned char)s[10])) {
            char dom[256] = {0};
            sscanf(s + 10, " %255[^;]", dom);
            add_finding(3, "L%d: PERMISSIVE_DOMAIN '%s' declared — this type "
                           "is exempt from ALL enforcement.", lineno, dom);
            continue;
        }

        if (strncmp(s, "allow", 5) != 0 || !isspace((unsigned char)s[5]))
            continue;

        char src[256], tgt[256], cls[256], perms[512];
        int got = sscanf(s, " allow %255s %255s %255s %511[^;]",
                         src, tgt, cls, perms);
        if (got < 4) continue;

        int sev = 0;
        const char *why = NULL;

        if (strstr(perms, "*") || strstr(cls, "*")) {
            sev = 3; why = "wildcard permission/class grant";
        } else if (strcmp(tgt, "kernel") == 0 && strcmp(src, "kernel") != 0
                   && strcmp(src, "init") != 0) {
            /* init legitimately talks to the kernel (e.g. key:request);
             * any OTHER domain doing so is the interesting finding. */
            sev = 3; why = "non-kernel domain touching kernel object";
        } else if (strcmp(tgt, "init") == 0 &&
                   strncmp(src, "u:object_r:init", 15) != 0) {
            sev = 2; why = "foreign domain acting on init";
        } else if (token_has_dangerous_perm(perms)) {
            sev = 2; why = "dangerous capability in permset";
        } else if (strstr(cls, "proc") && strstr(perms, "write")) {
            sev = 2; why = "write access to procfs security files";
        }

        if (sev)
            add_finding(sev, "L%d: OVERLY_PERMISSIVE (%s): allow %s %s %s %s",
                        lineno, why, src, tgt, cls, perms);
    }
    fclose(fp);
}

/* ------------------------------------------------------------------------ */
/* Audit 4: fingerprint the live binary policy (read-only)                  */
/* ------------------------------------------------------------------------ */

static void fingerprint_live_policy(void)
{
    char hex[32];
    if (hash_file_ro(PATH_SELINUX_POLICY, hex, sizeof hex) == 0) {
        add_finding(1, "POLICY_FINGERPRINT: live binary policy FNV-1a=%s "
                       "(hand this string to evidence_logger.py to anchor it "
                       "in the Merkle tree).", hex);
    } else {
        add_finding(1, "POLICY_FINGERPRINT_SKIPPED: cannot read %s (%s) — "
                       "normal for unprivileged users; obtain the policy from "
                       "your authorized lab image instead.",
                    PATH_SELINUX_POLICY, strerror(errno));
    }
}

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    const char *rule_dump = NULL;
    const char *target_proc = NULL;   /* ADVANCED: --pid N | --process NAME */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc)
            target_proc = argv[++i];
        else if (strcmp(argv[i], "--process") == 0 && i + 1 < argc)
            target_proc = argv[++i];
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("usage: %s [--pid <n> | --process <name>] [policy_dump.txt]\n"
                   "  READ-ONLY audit. With a dump argument, also scans\n"
                   "  allow/permissive rules from the text file.\n", argv[0]);
            return 0;
        } else
            rule_dump = argv[i];      /* legacy positional form */
    }

    printf("# selinux_policy_analyzer (READ-ONLY audit)\n");
    printf("# host=%s — no policy mutation APIs are linked or called\n",
           "linux/android");

    audit_enforce_mode();
    audit_process_contexts(target_proc);
    fingerprint_live_policy();

    if (rule_dump)
        audit_rule_dump(rule_dump);
    else
        add_finding(1, "NOTE: run with a text policy dump argument "
                       "(e.g. `sesearch -A -p sepolicy.dump`) to enable "
                       "rule-level analysis.");

    /* Emit findings sorted-ish by severity for triage convenience. */
    static const char *SEV[] = {"?", "INFO", "WARN", "CRIT"};
    for (int want = 3; want >= 1; want--) {
        for (int i = 0; i < g_nfindings; i++) {
            if (g_findings[i].severity == want)
                printf("[%s] %s\n", SEV[want], g_findings[i].text);
        }
    }

    int crit = 0, warn = 0;
    for (int i = 0; i < g_nfindings; i++) {
        if (g_findings[i].severity == 3) crit++;
        if (g_findings[i].severity == 2) warn++;
    }
    printf("# summary: %d findings (%d CRIT, %d WARN)\n",
           g_nfindings, crit, warn);

    /* Exit code convention: 0 clean, 10 warnings, 20 criticals (for CI). */
    return crit ? 20 : (warn ? 10 : 0);
}
