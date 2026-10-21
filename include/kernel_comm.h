/* kernel_comm.h - Controlled, read-only kernel telemetry interface.
 *
 * Kernel-X Research Toolkit (lab/educational build).
 *
 * This module abstracts "how do we learn about the kernel" for the audit
 * tooling. It supports exactly three observation channels, all READ-ONLY:
 *
 *   1. proc_telemetry : /proc/version, /proc/config.gz, /proc/kallsyms
 *                       (symbol NAMES only - never addresses of interest to
 *                        an attacker; used to detect whether kptr_restrict
 *                        is doing its job).
 *   2. kcore_probe    : stat-only probe of /proc/kcore. The toolkit NEVER
 *                       opens or maps /proc/kcore; it merely reports whether
 *                       the node exists and what protection would apply.
 *                       (Mapping kcore is a classic credential-theft path in
 *                       the literature; documenting its guardrails is the
 *                       educational point.)
 *   3. property_query : Android `getprop` style queries via __system_property
 *                       when built for Android/Bionic, with a portable
 *                       fallback that reads /system/build.prop-style files
 *                       on Linux lab images.
 *
 * Everything returns structured results and error codes; nothing here can
 * modify kernel state. There are no ioctl() calls into driver nodes, no
 * write(2) to anything under /sys or /proc, and no module loading.
 */
#ifndef KX_KERNEL_COMM_H
#define KX_KERNEL_COMM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Error codes ---------------------------------------------------------- */
#define KX_KC_OK             0
#define KX_KC_EINVAL        (-1)
#define KX_KC_EPERM         (-2)   /* EACCES/EPERM reading telemetry node */
#define KX_KC_ENODEV        (-3)   /* node absent (non-Linux/container) */
#define KX_KC_EUNTRUSTED    (-4)   /* channel disabled by sandbox policy */

/* ---- Kernel telemetry snapshot -------------------------------------------- */
typedef struct kx_kernel_info {
    char release[128];        /* uname release, e.g. "5.15.123-android13-8..." */
    char version[256];        /* full /proc/version line                    */
    int  android_api_level;   /* parsed from prop, -1 if unknown            */
    char security_patch[16];  /* ro.build.version.security_patch or ""      */
    char abi[32];             /* arm64-v8a / armeabi-v7a / x86_64 / ""      */
    int  kptr_restrict;       /* /proc/sys/kernel/kptr_restrict value, -1   */
    int  selinux_enforcing;   /* 1 enforcing, 0 permissive, -1 unavailable  */
    int  kcore_present;       /* 1 if /proc/kcore node exists (stat only)   */
    int  gki_candidate;       /* heuristic: release contains "-android"     */
} kx_kernel_info_t;

/* Populate info using only safe channels. Missing nodes are tolerated and
 * marked with sentinel values; the function itself only fails hard on NULL. */
int kx_kc_collect_kernel_info(kx_kernel_info_t *info);

/* Read one sysctl-style text node (e.g. /proc/sys/kernel/kptr_restrict).
 * Returns KX_KC_OK and writes a NUL-terminated trimmed value into out.
 * Length-bounded; refuses paths outside /proc/sys and /proc/robotfs-free
 * allowlist enforced internally. */
int kx_kc_read_sysctl(const char *path, char *out, size_t outlen);

/* Query an Android system property by name. On non-Android builds this
 * consults $KX_PROP_OVERRIDE_FILE (a simple key=value file) so lab tests can
 * simulate device properties without touching a real device. */
int kx_kc_get_prop(const char *name, char *out, size_t outlen);

/* Report whether the ptrace channel is *available but intentionally unused*.
 * The toolkit links ptrace symbols for educational completeness; calling
 * this function simply describes policy: it always returns KX_KC_EUNTRUSTED
 * unless the sandbox profile explicitly enabled inspection mode. */
int kx_kc_ptrace_policy(char *out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif /* KX_KERNEL_COMM_H */
