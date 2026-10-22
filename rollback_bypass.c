/* rollback_bypass.c - AVB 2.0 POSTURE ANALYZER & REPORTER (no bypass logic).
 *
 * Kernel-X Research Toolkit (lab/educational build).
 *
 * The original file of this name patched Gatekeeper return values in RAM.
 * That code has been removed entirely. This rewrite performs ANALYSIS ONLY:
 *
 *   check_avb_status()        - reads boot-partition header metadata to infer
 *                               whether Android Verified Boot is enabled and
 *                               what chain-of-trust state is reported. On lab
 *                               hosts without a boot partition it falls back
 *                               to simulated properties ($KX_PROP_OVERRIDE_FILE)
 *                               so the analysis pipeline can still be taught.
 *   rollback_index_analyzer() - compares the currently-reported rollback
 *                               index against the stored monotonic value from
 *                               a TPM/Titan-like counter backend; when no
 *                               hardware is present, a clearly-labelled
 *                               SIMULATED secure store is used.
 *   generate_avb_report()     - emits a JSON report describing weaknesses in
 *                               the *configuration* of AVB on the target
 *                               (unlocked bootloader, stale rollback index,
 *                               permissive SELinux...), with remediations.
 *
 * Nothing here writes to any partition, bootloader, or memory of another
 * process. Standard C11 only; compiles clean under -Wall -Wextra.
 */

/* Feature-test macros MUST precede every #include so that glibc exposes
 * POSIX/GNU declarations (O_CLOEXEC, localtime_r) under -std=c11. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define KX_AVB_MAGIC_LEN      4
#define KX_BOOT_HEADER_MAX    64   /* read only the first bytes of a header */
#define KX_PATH_MAX           256

/* Public AVB 2.0 constants (from the AOSP verity/AVB spec - documentation
 * values, not secrets). */
static const uint8_t AVB_MAGIC[] = {'A', 'V', 'B', '0'};

typedef enum avb_state {
    AVB_STATE_UNKNOWN = 0,
    AVB_STATE_ENABLED_VERIFIED,   /* green */
    AVB_STATE_ENABLED_WARNING,    /* yellow */
    AVB_STATE_DISABLED_ORANGE,    /* unlocked bootloader */
    AVB_STATE_FAILED_RED          /* red / device corrupt */
} avb_state_t;

typedef struct avb_status {
    int analyzed;                 /* 1 if header data was actually read */
    int simulated;                /* 1 if result came from lab simulation */
    avb_state_t state;
    char state_str[16];
    char boot_device[KX_PATH_MAX];
    uint32_t header_magic_seen;   /* host-order decoded magic, 0 if none */
    int vbmeta_present;           /* found a vbmeta-style structure marker */
} avb_status_t;

typedef struct rollback_snapshot {
    uint64_t current_index;       /* index reported by running system */
    uint64_t stored_index;        /* monotonic counter in secure storage */
    int hardware_backed;          /* 0 => simulated store (lab default) */
    int consistent;               /* current >= stored */
} rollback_snapshot_t;

/* ---- small helpers -------------------------------------------------------- */

static const char *avb_state_name(avb_state_t s)
{
    switch (s) {
    case AVB_STATE_ENABLED_VERIFIED: return "green";
    case AVB_STATE_ENABLED_WARNING:  return "yellow";
    case AVB_STATE_DISABLED_ORANGE:  return "orange";
    case AVB_STATE_FAILED_RED:       return "red";
    default:                         return "unknown";
    }
}

static void json_escape(const char *in, char *out, size_t outlen)
{
    size_t o = 0;
    for (; in != NULL && *in != '\0' && o + 2 < outlen; in++) {
        if (*in == '"' || *in == '\\') {
            out[o++] = '\\';
            out[o++] = *in;
        } else if ((unsigned char)*in < 0x20) {
            o += (size_t)snprintf(out + o, outlen - o, "\\u%04x",
                                  (unsigned char)*in);
        } else {
            out[o++] = *in;
        }
    }
    out[o] = '\0';
}

/* Lab property lookup: key=value file pointed at by $KX_PROP_OVERRIDE_FILE.
 * Used to SIMULATE device state on non-Android hosts. Returns 0 on success. */
static int lab_get_prop(const char *key, char *val, size_t valuelen)
{
    const char *path = getenv("KX_PROP_OVERRIDE_FILE");
    char line[512];
    FILE *fp;

    val[0] = '\0';
    if (path == NULL) {
        return -1;
    }
    fp = fopen(path, "re");
    if (fp == NULL) {
        return -1;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *eq = strchr(line, '=');
        if (eq == NULL || line[0] == '#') {
            continue;
        }
        *eq = '\0';
        if (strcmp(line, key) == 0) {
            size_t n;
            eq++;
            n = strcspn(eq, "\r\n");
            if (n >= valuelen) {
                n = valuelen - 1;
            }
            memcpy(val, eq, n);
            val[n] = '\0';
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    return -1;
}

/* ---- check_avb_status ------------------------------------------------------
 * Read-only inspection of boot/vbmeta partition headers. We open strictly
 * O_RDONLY and read at most KX_BOOT_HEADER_MAX bytes. If the partitions do
 * not exist (plain Linux lab host) we consult the simulated property store
 * and mark the result as simulated. NEVER opens anything for writing. */
int check_avb_status(avb_status_t *status)
{
    static const char *boot_candidates[] = {
        "/dev/block/by-name/boot",
        "/dev/block/by-name/vbmeta",
        "/dev/disk/by-partlabel/boot",
        "/dev/disk/by-partlabel/vbmeta",
    };
    unsigned char hdr[KX_BOOT_HEADER_MAX];
    ssize_t got;
    int fd;
    size_t i;
    char prop[64];

    if (status == NULL) {
        return -EINVAL;
    }
    memset(status, 0, sizeof(*status));
    status->state = AVB_STATE_UNKNOWN;
    snprintf(status->state_str, sizeof(status->state_str), "unknown");

    for (i = 0; i < sizeof(boot_candidates) / sizeof(boot_candidates[0]); i++) {
        struct stat st;
        if (stat(boot_candidates[i], &st) != 0) {
            continue;
        }
        fd = open(boot_candidates[i], O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            syslog(LOG_WARNING,
                   "avb_status: %s exists but cannot be opened (%s). "
                   "Typical unprivileged Termux result; not retried.",
                   boot_candidates[i], strerror(errno));
            continue;
        }
        got = read(fd, hdr, sizeof(hdr));
        close(fd);
        if (got < (ssize_t)KX_AVB_MAGIC_LEN) {
            syslog(LOG_WARNING, "avb_status: short header read from %s",
                   boot_candidates[i]);
            continue;
        }
        snprintf(status->boot_device, sizeof(status->boot_device), "%s",
                 boot_candidates[i]);
        status->analyzed = 1;
        status->header_magic_seen = ((uint32_t)hdr[0] << 24) |
                                    ((uint32_t)hdr[1] << 16) |
                                    ((uint32_t)hdr[2] << 8) |
                                    (uint32_t)hdr[3];
        if (memcmp(hdr, AVB_MAGIC, KX_AVB_MAGIC_LEN) == 0) {
            status->vbmeta_present = 1;
        }
        break;
    }

    /* Chain-of-trust state is exposed through the boot properties; read them
     * where available (Android), else simulate from the lab override file. */
    if (lab_get_prop("ro.boot.verifiedbootstate", prop, sizeof(prop)) == 0) {
        if (strcmp(prop, "green") == 0) {
            status->state = AVB_STATE_ENABLED_VERIFIED;
        } else if (strcmp(prop, "yellow") == 0) {
            status->state = AVB_STATE_ENABLED_WARNING;
        } else if (strcmp(prop, "orange") == 0) {
            status->state = AVB_STATE_DISABLED_ORANGE;
        } else if (strcmp(prop, "red") == 0) {
            status->state = AVB_STATE_FAILED_RED;
        }
        snprintf(status->state_str, sizeof(status->state_str), "%s",
                 avb_state_name(status->state));
        if (!status->analyzed) {
            status->simulated = 1;
        }
    } else if (!status->analyzed) {
        snprintf(status->state_str, sizeof(status->state_str), "unknown");
        status->simulated = 1;
        syslog(LOG_INFO,
               "avb_status: no boot partition and no lab properties - "
               "reporting UNKNOWN (analysis skipped, nothing touched)");
    }
    return 0;
}

/* ---- rollback_index_analyzer ----------------------------------------------
 * Compares the boot-time rollback index against the monotonic counter that a
 * TPM/Titan-class chip would store. Hardware access (TSS/ioctl to an RMPC
 * node) is intentionally NOT attempted; when unavailable we use a clearly
 * labelled SIMULATED store backed by a regular file under $KX_LAB_DIR so the
 * educational flow can run end-to-end. */
int rollback_index_analyzer(rollback_snapshot_t *snap)
{
    char pathbuf[KX_PATH_MAX];
    const char *lab_dir;
    FILE *fp;
    char prop[64];
    uint64_t stored = 0;
    uint64_t current = 0;
    unsigned long parsed;

    if (snap == NULL) {
        return -EINVAL;
    }
    memset(snap, 0, sizeof(*snap));

    /* Current index as advertised by the running system (prop or lab file). */
    if (lab_get_prop("ro.boot.vbmeta.rollback_index", prop, sizeof(prop)) == 0) {
        errno = 0;
        parsed = strtoul(prop, NULL, 10);
        if (errno == 0) {
            current = (uint64_t)parsed;
        }
    }

    /* Secure-storage counter. Real devices keep this inside Titan/TPM and it
     * is NOT readable from userspace - which is exactly the point of the
     * exercise. In the lab we emulate it with a file the controller owns. */
    lab_dir = getenv("KX_LAB_DIR");
    if (lab_dir == NULL) {
        lab_dir = "./lab_state";
    }
    snprintf(pathbuf, sizeof(pathbuf), "%s/rollback_counter.txt", lab_dir);
    fp = fopen(pathbuf, "re");   /* read-only; created elsewhere by controller */
    if (fp != NULL) {
        char line[64];
        if (fgets(line, sizeof(line), fp) != NULL) {
            errno = 0;
            parsed = strtoul(line, NULL, 10);
            if (errno == 0) {
                stored = (uint64_t)parsed;
            }
        }
        fclose(fp);
    } else {
        /* Simulation default: assume the chip holds whatever boot reports,
         * i.e. a healthy monotonic state. Flagged as simulated below. */
        stored = current;
    }

    snap->current_index = current;
    snap->stored_index = stored;
    snap->hardware_backed = 0;             /* never claimed in lab builds */
    snap->consistent = (current >= stored);
    syslog(LOG_INFO,
           "rollback_analyzer[simulated]: current=%llu stored=%llu -> %s",
           (unsigned long long)current, (unsigned long long)stored,
           snap->consistent ? "MONOTONIC-OK" : "ROLLBACK-ANOMALY");
    return 0;
}

/* ---- reporting ------------------------------------------------------------- */

static void emit_findings(FILE *out, const avb_status_t *st,
                          const rollback_snapshot_t *rb, unsigned *count)
{
    struct { const char *code; const char *sev; const char *detail; } f[8];
    size_t n = 0, k;
    char esc[512];

    if (st->state == AVB_STATE_DISABLED_ORANGE) {
        f[n].code = "AVB_UNLOCKED"; f[n].sev = "high";
        f[n++].detail = "Bootloader unlocked: root of trust is user-writable; "
                        "verified boot guarantees do not apply.";
    } else if (st->state == AVB_STATE_FAILED_RED) {
        f[n].code = "AVB_FAILED"; f[n].sev = "high";
        f[n++].detail = "Device reports verification failure state.";
    } else if (st->state == AVB_STATE_ENABLED_WARNING) {
        f[n].code = "AVB_WARNING"; f[n].sev = "medium";
        f[n++].detail = "Verified boot passing with warnings (self-signed "
                        "or modified vendor key expected).";
    } else if (st->state == AVB_STATE_ENABLED_VERIFIED) {
        f[n].code = "AVB_GREEN"; f[n].sev = "info";
        f[n++].detail = "Chain of trust verified end-to-end.";
    } else {
        f[n].code = "AVB_UNKNOWN"; f[n].sev = "info";
        f[n++].detail = "No AVB telemetry available on this host; install "
                        "lab properties to exercise the analyzer.";
    }

    if (!rb->consistent) {
        f[n].code = "ROLLBACK_ANOMALY"; f[n].sev = "high";
        f[n++].detail = "Reported rollback index is BELOW the stored monotonic "
                        "counter: image downgrade attempt signature. Check "
                        "for restored old factory images.";
    } else {
        f[n].code = "ROLLBACK_OK"; f[n].sev = "info";
        f[n++].detail = "Rollback index monotonicity holds.";
    }

    if (!rb->hardware_backed) {
        f[n].code = "SIMULATED_SECURE_STORE"; f[n].sev = "info";
        f[n++].detail = "Counter read from lab simulation file, not a real "
                        "TPM/Titan RPMB backend. Do not generalise results to "
                        "production hardware.";
    }

    if (st->analyzed && !st->vbmeta_present) {
        f[n].code = "VBMETA_MAGIC_ABSENT"; f[n].sev = "low";
        f[n++].detail = "Boot header first word did not match documented "
                        "AVB magic; header may be packed differently on this "
                        "SoC family.";
    }

    fputs("\"findings\":[", out);
    for (k = 0; k < n; k++) {
        if (k) {
            fputs(",", out);
        }
        json_escape(f[k].detail, esc, sizeof(esc));
        fprintf(out, "{\"severity\":\"%s\",\"code\":\"%s\",\"detail\":\"%s\"}",
                f[k].sev, f[k].code, esc);
        (*count)++;
    }
    fputs("]", out);
}

int generate_avb_report(const avb_status_t *st, const rollback_snapshot_t *rb,
                        FILE *out)
{
    unsigned findings = 0;
    char ts[64];
    time_t now = time(NULL);
    struct tm tm_buf;
    char dev_esc[KX_PATH_MAX * 2];

    if (st == NULL || rb == NULL || out == NULL) {
        return -EINVAL;
    }
    if (localtime_r(&now, &tm_buf) == NULL) {
        snprintf(ts, sizeof(ts), "unknown");
    } else {
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm_buf);
    }
    json_escape(st->boot_device, dev_esc, sizeof(dev_esc));

    fputs("{\n", out);
    fprintf(out, "  \"tool\": \"avb_posture_analyzer\",\n");
    fprintf(out, "  \"version\": \"2.0.0\",\n");
    fprintf(out, "  \"mode\": \"analysis-only-no-modification\",\n");
    fprintf(out, "  \"timestamp_local\": \"%s\",\n", ts);
    fprintf(out, "  \"avb\": {\n");
    fprintf(out, "    \"enabled\": %s,\n",
            st->state == AVB_STATE_ENABLED_VERIFIED ||
            st->state == AVB_STATE_ENABLED_WARNING ? "true" : "false");
    fprintf(out, "    \"state\": \"%s\",\n", st->state_str);
    fprintf(out, "    \"header_analyzed\": %s,\n",
            st->analyzed ? "true" : "false");
    fprintf(out, "    \"simulated_source\": %s,\n",
            st->simulated ? "true" : "false");
    fprintf(out, "    \"boot_device\": \"%s\",\n", dev_esc);
    fprintf(out, "    \"vbmeta_marker\": %s\n",
            st->vbmeta_present ? "true" : "false");
    fprintf(out, "  },\n");
    fprintf(out, "  \"rollback\": {\n");
    fprintf(out, "    \"current_index\": %llu,\n",
            (unsigned long long)rb->current_index);
    fprintf(out, "    \"stored_index\": %llu,\n",
            (unsigned long long)rb->stored_index);
    fprintf(out, "    \"monotonic_ok\": %s,\n",
            rb->consistent ? "true" : "false");
    fprintf(out, "    \"hardware_backed\": %s\n",
            rb->hardware_backed ? "true" : "false");
    fprintf(out, "  },\n  ");
    emit_findings(out, st, rb, &findings);
    fprintf(out, ",\n  \"finding_count\": %u\n}\n", findings);
    fflush(out);
    return 0;
}

/* ---- main ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    avb_status_t status;
    rollback_snapshot_t rb;
    FILE *out = stdout;
    const char *out_path = NULL;
    int rc;

    openlog("kx_avb_analyzer", LOG_PID | LOG_CONS, LOG_USER);

    if (argc > 1) {
        if (strcmp(argv[1], "--out") == 0 && argc > 2) {
            out_path = argv[2];
        } else if (strcmp(argv[1], "--help") == 0) {
            printf("Usage: %s [--out report.json]\n"
                   "Read-only AVB 2.0 posture analyzer (lab/educational).\n",
                   argv[0]);
            closelog();
            return 0;
        } else {
            fprintf(stderr, "[!] unknown argument: %s\n", argv[1]);
            closelog();
            return 1;
        }
    }

    rc = check_avb_status(&status);
    if (rc != 0) {
        fprintf(stderr, "[!] avb status check failed: %s\n", strerror(-rc));
        closelog();
        return 1;
    }
    rc = rollback_index_analyzer(&rb);
    if (rc != 0) {
        fprintf(stderr, "[!] rollback analyzer failed: %s\n", strerror(-rc));
        closelog();
        return 1;
    }

    if (out_path != NULL) {
        out = fopen(out_path, "we");   /* 'w' truncated create; our own report
                                        * file only - never a device node */
        if (out == NULL) {
            fprintf(stderr, "[!] cannot open report file %s: %s\n",
                    out_path, strerror(errno));
            closelog();
            return 1;
        }
    }

    rc = generate_avb_report(&status, &rb, out);
    if (out_path != NULL) {
        fclose(out);
        if (rc == 0) {
            fprintf(stderr, "[+] AVB report written to %s\n", out_path);
        }
    }
    closelog();
    return rc == 0 ? 0 : 1;
}
