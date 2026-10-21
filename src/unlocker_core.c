/* unlocker_core.c - Kernel-X Research Toolkit: read-only audit orchestrator.
 *
 * LEGACY NAME NOTICE: this binary used to be an "unlocker". The v2 rewrite
 * removed every mutation/bypass routine. What ships now is a defensive audit
 * driver that:
 *   1. collects kernel/AVB telemetry (kernel_comm.h),
 *   2. optionally observes one operator-supplied PID's memory-map metadata
 *      through the strictly read-only helpers in memory_utils.h,
 *   3. runs the dry_run analysis state machine from exploit_logic.h,
 *   4. emits a JSON report for the local dashboard.
 *
 * Safety properties:
 *   - dry_run defaults ON; --no-dry-run still performs no writes because no
 *     write path exists in this build (kx_mem_refused_write always refuses).
 *   - ptrace is NEVER called. Policy string available via --show-policy.
 *   - /proc/kcore is never opened; only its existence is reported.
 *   - Compatible with Android 12/13/14 (API 31+) kernels when run on them,
 *     and degrades gracefully on plain Linux lab hosts and Termux.
 *   - All significant events go to syslog (LOG_USER) for lab evidence trails.
 *
 * Build:  gcc -std=c11 -Wall -Wextra -O2 -Iinclude \
 *             src/unlocker_core.c src/memory_utils.c src/kernel_comm.c \
 *             src/exploit_logic.c -o bin/kernel_x_audit
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "exploit_logic.h"
#include "kernel_comm.h"
#include "memory_utils.h"

#define KX_WRITE_TOKEN "" /* intentionally empty: no token can enable writes
                            * in the educational build. main_controller.sh may
                            * compile a lab variant with a real token. */

static void usage(const char *argv0)
{
    printf(
        "Kernel-X audit core (read-only) - educational lab tool\n"
        "Usage: %s [options]\n"
        "  --pid <N>            observe process N's maps metadata (read-only)\n"
        "  --dry-run            simulation mode (DEFAULT, always safe)\n"
        "  --no-dry-run         keep observation mode; note: NO write path\n"
        "                       exists in this build regardless\n"
        "  --budget-mib <1-512> per-process observation budget\n"
        "  --allow-write-token <t>  authorization stub (rejected unless a\n"
        "                       lab build was compiled with token t)\n"
        "  --scan-mem           also sample readable regions via O_RDONLY\n"
        "                       /proc/<pid>/mem (signature scan, no export)\n"
        "  --show-policy        print the ptrace/kcore policy and exit\n"
        "  --quiet              reduce syslog chatter\n", argv0);
}

int main(int argc, char *argv[])
{
    kx_audit_config_t cfg;
    kx_audit_session_t session;
    int do_scan_mem = 0;
    int i;

    openlog("kernel_x_audit", LOG_PID | LOG_CONS, LOG_USER);

    /* Pre-scan for the informational flags before strict parsing. */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--scan-mem") == 0) {
            do_scan_mem = 1;
        } else if (strcmp(argv[i], "--show-policy") == 0) {
            char policy[512];
            kx_kc_ptrace_policy(policy, sizeof(policy));
            printf("%s\n", policy);
            closelog();
            return 0;
        }
    }

    /* Rebuild argv without --scan-mem so the config parser stays strict. */
    {
        char **clean = calloc((size_t)(argc > 0 ? argc : 1), sizeof(char *));
        int j = 0, rc;
        if (clean == NULL) {
            fprintf(stderr, "[!] out of memory\n");
            closelog();
            return 1;
        }
        clean[j++] = argv[0];
        for (i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--scan-mem") != 0) {
                clean[j++] = argv[i];
            }
        }
        rc = kx_audit_config_parse(&cfg, j, clean, KX_WRITE_TOKEN);
        free(clean);
        if (rc != 0) {
            usage(argv[0]);
            closelog();
            return 1;
        }
    }
    if (argc <= 1) {
        usage(argv[0]);
        /* fallthrough: a bare invocation still runs a harmless telemetry pass */
    }

    if (kx_audit_session_init(&session, &cfg) != KX_MEM_OK) {
        fprintf(stderr, "[!] failed to initialise audit session\n");
        closelog();
        return 1;
    }

    (void)kx_audit_analyze_verified_boot_posture(&session);
    (void)kx_audit_analyze_gatekeeper_posture(&session);

    if (do_scan_mem && cfg.target_pid > 0) {
        /* Demonstration of the guarded read pipeline: validate then read.
         * In dry_run we only enumerate mappings; we skip actual byte reads
         * so even the observation footprint matches what we promise. */
        kx_mem_ctx_t *ctx = kx_mem_open(cfg.target_pid, cfg.scan_budget_bytes);
        if (ctx == NULL) {
            kx_audit_record_finding(
                &session, KX_SEV_INFO, "MEM_OPEN_DENIED_OR_ABSENT",
                "could not obtain read-only context on target pid "
                "(expected under SELinux enforcing or if pid exited)");
        } else {
            kx_mem_region_t region;
            uint64_t probe = 0x1000; /* first page of the address space */
            int rc = kx_mem_validate_addr(ctx, probe, &region);
            if (rc == KX_MEM_OK && !cfg.dry_run) {
                unsigned char sample[64];
                size_t nread = 0;
                rc = kx_mem_read(ctx, region.start, sample, sizeof(sample),
                                 &nread);
                if (rc == KX_MEM_OK) {
                    kx_audit_record_finding(
                        &session, KX_SEV_INFO, "MEM_READ_OK",
                        "guarded pread succeeded on first mapped page; "
                        "contents retained in-process only, never exported");
                } else {
                    kx_audit_record_finding(
                        &session, KX_SEV_INFO, "MEM_READ_FAULTED",
                        "read faulted safely (budget/denial/unmapped); "
                        "target process unaffected");
                }
            } else if (rc == KX_MEM_OK && cfg.dry_run) {
                kx_audit_record_finding(
                    &session, KX_SEV_INFO, "MEM_DRYRUN_SKIPPED",
                    "dry_run active: mapping validated, byte read skipped");
            } else {
                kx_audit_record_finding(
                    &session, KX_SEV_INFO, "MEM_ADDR_INVALID",
                    "probe address unmapped - validation prevented a wild "
                    "pointer dereference (this is the safety property demo)");
            }
            /* Even if some caller logic asked for a write, it is refused. */
            (void)kx_mem_refused_write(region.start);
            kx_mem_close(ctx);
        }
    }

    (void)kx_audit_simulate_remediation_walkthrough(&session);

    if (kx_audit_emit_json_report(&session) != KX_MEM_OK) {
        fprintf(stderr, "[!] report emission failed\n");
        closelog();
        return 1;
    }

    syslog(LOG_INFO, "audit run complete (dry_run=%d, writes_possible=0)",
           cfg.dry_run);
    closelog();
    return 0;
}
