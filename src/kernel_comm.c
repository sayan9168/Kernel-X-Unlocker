/* kernel_comm.c - Read-only kernel telemetry implementation.
 *
 * Channels implemented (all read-only, all failure-tolerant):
 *   /proc/version, /proc/sys allowlisted nodes, SELinux status file,
 *   stat-only /proc/kcore probe, and a property query with an Android
 *   Bionic path (__system_property_find/get) guarded by #ifdef so the same
 *   source builds on glibc lab hosts.
 */
#include "kernel_comm.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#ifdef __ANDROID__
#include <sys/system_properties.h>
#define KX_PROP_BUF_SIZE PROP_VALUE_MAX
#else
#define KX_PROP_BUF_SIZE 92   /* Bionic's historical PROP_VALUE_MAX */
#endif

static void trim(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) {
        s[--n] = '\0';
    }
}

int kx_kc_read_sysctl(const char *path, char *out, size_t outlen)
{
    int fd;
    ssize_t got;
    const char *prefixes[] = {"/proc/sys/", "/proc/version", "/sys/fs/selinux/"};
    size_t i, allow = 0;

    if (path == NULL || out == NULL || outlen == 0) {
        return KX_KC_EINVAL;
    }
    /* Allowlist: refuse arbitrary paths so this helper can never be steered
     * into device nodes or writable sysfs knobs. */
    for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        if (strncmp(path, prefixes[i], strlen(prefixes[i])) == 0) {
            allow = 1;
            break;
        }
    }
    if (!allow) {
        syslog(LOG_WARNING, "read_sysctl: refusing non-allowlisted path %s",
               path);
        return KX_KC_EPERM;
    }

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            return KX_KC_ENODEV;
        }
        syslog(LOG_WARNING, "read_sysctl: %s -> %s", path, strerror(errno));
        return KX_KC_EPERM;
    }
    got = read(fd, out, outlen - 1);
    close(fd);
    if (got < 0) {
        out[0] = '\0';
        return KX_KC_EPERM;
    }
    out[got] = '\0';
    trim(out);
    return KX_KC_OK;
}

int kx_kc_get_prop(const char *name, char *out, size_t outlen)
{
    if (name == NULL || out == NULL || outlen == 0) {
        return KX_KC_EINVAL;
    }
    out[0] = '\0';

#ifdef __ANDROID__
    {
        char val[PROP_VALUE_MAX];
        if (__system_property_get(name, val) > 0 && val[0] != '\0') {
            snprintf(out, outlen, "%s", val);
            return KX_KC_OK;
        }
    }
#endif
    /* Portable fallback: $KX_PROP_OVERRIDE_FILE is a key=value file used by
     * the lab controller to simulate device properties on plain Linux. */
    {
        const char *ovr = getenv("KX_PROP_OVERRIDE_FILE");
        FILE *fp;
        char line[512];
        int rc = KX_KC_ENODEV;

        if (ovr == NULL) {
            ovr = "/workspace/lab_props.conf";
        }
        fp = fopen(ovr, "re");
        if (fp == NULL) {
            return KX_KC_ENODEV;
        }
        while (fgets(line, sizeof(line), fp) != NULL) {
            char *eq;
            char *key;
            if (line[0] == '#' || line[0] == '\n') {
                continue;
            }
            eq = strchr(line, '=');
            if (eq == NULL) {
                continue;
            }
            *eq = '\0';
            key = line;
            trim(key);
            if (strcmp(key, name) == 0) {
                char *v = eq + 1;
                size_t n;
                trim(v);
                n = strlen(v);
                if (n >= outlen) {
                    n = outlen - 1;
                }
                memcpy(out, v, n);
                out[n] = '\0';
                rc = KX_KC_OK;
                break;
            }
        }
        fclose(fp);
        return rc;
    }
}

int kx_kc_ptrace_policy(char *out, size_t outlen)
{
    static const char policy[] =
        "ptrace channel: linked for educational completeness but DISABLED by "
        "toolkit policy. The audit engine observes processes through "
        "/proc/<pid>/maps metadata and O_RDONLY /proc/<pid>/mem only; it never "
        "attaches, stops, injects into, or signals a target.";
    if (out == NULL || outlen == 0) {
        return KX_KC_EINVAL;
    }
    snprintf(out, outlen, "%s", policy);
    return KX_KC_EUNTRUSTED; /* always reports "not trusted for attach" */
}

int kx_kc_collect_kernel_info(kx_kernel_info_t *info)
{
    char tmp[256];
    long v;
    char prop_buf[KX_PROP_BUF_SIZE];

    if (info == NULL) {
        return KX_KC_EINVAL;
    }
    memset(info, 0, sizeof(*info));
    info->android_api_level = -1;
    info->kptr_restrict = -1;
    info->selinux_enforcing = -1;
    info->kcore_present = 0;

    /* release via uname-equivalent node (works in containers too) */
    if (kx_kc_read_sysctl("/proc/version", info->version,
                          sizeof(info->version)) != KX_KC_OK) {
        info->version[0] = '\0';
    }
    /* extract the release token from "Linux version X.Y.Z ..." */
    {
        const char *p = strstr(info->version, "version ");
        if (p != NULL) {
            p += 7;
            while (*p == ' ') p++;
            size_t n = strcspn(p, " \t\n");
            if (n >= sizeof(info->release)) n = sizeof(info->release) - 1;
            memcpy(info->release, p, n);
            info->release[n] = '\0';
        }
    }
    info->gki_candidate = strstr(info->release, "-android") != NULL;

    if (kx_kc_read_sysctl("/proc/sys/kernel/kptr_restrict", tmp,
                          sizeof(tmp)) == KX_KC_OK) {
        v = strtol(tmp, NULL, 10);
        if (v >= 0 && v <= 2) {
            info->kptr_restrict = (int)v;
        }
    }

    if (kx_kc_read_sysctl("/sys/fs/selinux/enforce", tmp,
                          sizeof(tmp)) == KX_KC_OK) {
        info->selinux_enforcing = (tmp[0] == '1') ? 1 : 0;
    }

    /* stat-only kcore probe - we never open() it */
    {
        struct stat st;
        if (stat("/proc/kcore", &st) == 0 && S_ISREG(st.st_mode)) {
            info->kcore_present = 1;
            syslog(LOG_INFO,
                   "kcore_probe: node present (reported size %lld). Toolkit "
                   "policy forbids opening it; presence alone is telemetry.",
                   (long long)st.st_size);
        }
    }

    if (kx_kc_get_prop("ro.build.version.sdk", prop_buf,
                       sizeof(prop_buf)) == KX_KC_OK) {
        long api = strtol(prop_buf, NULL, 10);
        if (api > 0 && api < 100) {
            info->android_api_level = (int)api;
        }
    }
    if (kx_kc_get_prop("ro.build.version.security_patch",
                       info->security_patch,
                       sizeof(info->security_patch)) != KX_KC_OK) {
        info->security_patch[0] = '\0';
    }
    if (kx_kc_get_prop("ro.product.cpu.abi", info->abi,
                       sizeof(info->abi)) != KX_KC_OK) {
        snprintf(info->abi, sizeof(info->abi), "unknown");
    }
    return KX_KC_OK;
}
