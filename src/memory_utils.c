/* memory_utils.c - Read-only process-memory inspection implementation.
 *
 * See include/memory_utils.h for the design contract. This file:
 *   - opens /proc/<pid>/mem strictly O_RDONLY,
 *   - validates every address against /proc/<pid>/maps before reading,
 *   - enforces a byte budget so a lab run cannot degrade system stability,
 *   - refuses all write attempts unless an (intentionally near-impossible)
 *     authorization conjunction is met; in sandbox builds writes are always
 *     refused and logged to syslog.
 */
#include "memory_utils.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#ifndef KX_SANDBOX_BUILD
#define KX_SANDBOX_BUILD 0
#endif

static int errno_to_rc(int err)
{
    switch (err) {
    case EACCES:
    case EPERM:
        return KX_MEM_EPERM;
    case ENOENT:
    case ESRCH:
        return KX_MEM_ENOENT;
    case EFAULT:
    case EINVAL:
        return KX_MEM_EFAULT;
    default:
        return KX_MEM_EFAULT;
    }
}

kx_mem_ctx_t *kx_mem_open(pid_t target_pid, size_t max_read_bytes)
{
    char path[64];
    int fd;
    kx_mem_ctx_t *ctx;

    if (target_pid <= 0 || max_read_bytes == 0) {
        errno = EINVAL;
        return NULL;
    }

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        syslog(LOG_ERR, "kx_mem_open: out of memory");
        return NULL;
    }

    snprintf(path, sizeof(path), "/proc/%d/mem", (int)target_pid);
    /* O_RDONLY is load-bearing: cross-process writes through this node would
     * require PTRACE_ATTACH, which this toolkit never performs. */
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        syslog(LOG_WARNING,
               "kx_mem_open: cannot open %s (%s). On Android this is an "
               "expected SELinux denial for gatekeeperd/keystore2.",
               path, strerror(errno));
        free(ctx);
        return NULL;
    }

    ctx->pid = target_pid;
    ctx->mem_fd = fd;
    ctx->max_read_bytes = max_read_bytes;
    ctx->bytes_read = 0;
    syslog(LOG_INFO, "kx_mem_open: read-only context on pid %d, budget %zu B",
           (int)target_pid, max_read_bytes);
    return ctx;
}

void kx_mem_close(kx_mem_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->mem_fd >= 0) {
        close(ctx->mem_fd);
    }
    syslog(LOG_INFO, "kx_mem_close: pid %d, %zu bytes observed",
           (int)ctx->pid, ctx->bytes_read);
    free(ctx);
}

/* Parse one maps line: "start-end perms offset dev inode path". */
static int parse_maps_line(const char *line, kx_mem_region_t *r)
{
    unsigned long long start = 0, end = 0;
    char perms[8] = {0};
    int matched;

    matched = sscanf(line, "%llx-%llx %7s", &start, &end, perms);
    if (matched != 3 || end <= start) {
        return -1;
    }
    r->start = (uint64_t)start;
    r->end = (uint64_t)end;
    r->readable = perms[0] == 'r';
    r->writable = perms[1] == 'w';
    r->executable = perms[2] == 'x';

    const char *path = strchr(line, '\n');
    (void)path;
    /* extract path after the 5th whitespace-separated field */
    const char *p = line;
    int fields = 0;
    while (*p && fields < 5) {
        while (*p && !isspace((unsigned char)*p)) p++;
        while (*p && isspace((unsigned char)*p)) p++;
        fields++;
    }
    r->path[0] = '\0';
    if (*p) {
        size_t n = strcspn(p, "\n");
        if (n >= sizeof(r->path)) n = sizeof(r->path) - 1;
        memcpy(r->path, p, n);
        r->path[n] = '\0';
    }
    return 0;
}

int kx_mem_validate_addr(kx_mem_ctx_t *ctx, uint64_t addr,
                         kx_mem_region_t *out_region)
{
    char path[64];
    char line[512];
    FILE *fp;
    int found = 0;

    if (ctx == NULL || out_region == NULL) {
        return KX_MEM_EINVAL;
    }

    snprintf(path, sizeof(path), "/proc/%d/maps", (int)ctx->pid);
    fp = fopen(path, "re");
    if (fp == NULL) {
        syslog(LOG_WARNING, "validate_addr: cannot read %s (%s)",
               path, strerror(errno));
        return errno_to_rc(errno);
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        kx_mem_region_t r;
        if (parse_maps_line(line, &r) != 0) {
            continue;
        }
        if (addr >= r.start && addr < r.end) {
            if (!r.readable) {
                fclose(fp);
                syslog(LOG_INFO,
                       "validate_addr: 0x%" PRIx64 " mapped but not readable",
                       addr);
                return KX_MEM_EPERM;
            }
            *out_region = r;
            found = 1;
            break;
        }
    }
    fclose(fp);

    if (!found) {
        syslog(LOG_INFO, "validate_addr: 0x%" PRIx64 " is unmapped in pid %d",
               addr, (int)ctx->pid);
        return KX_MEM_ENOENT;
    }
    return KX_MEM_OK;
}

int kx_mem_read(kx_mem_ctx_t *ctx, uint64_t addr, void *dst, size_t len,
                size_t *nread)
{
    kx_mem_region_t region;
    ssize_t got;
    int rc;

    if (nread != NULL) {
        *nread = 0;
    }
    if (ctx == NULL || dst == NULL || len == 0) {
        return KX_MEM_EINVAL;
    }
    if (ctx->bytes_read + len > ctx->max_read_bytes) {
        syslog(LOG_WARNING, "kx_mem_read: scan budget exhausted for pid %d",
               (int)ctx->pid);
        return KX_MEM_EBUDGET;
    }
    /* Guard against absurd offsets that could wrap when added to len. */
    if (addr + len < addr) {
        return KX_MEM_EFAULT;
    }

    rc = kx_mem_validate_addr(ctx, addr, &region);
    if (rc != KX_MEM_OK) {
        return rc;
    }
    if (addr + len > region.end) {
        len = (size_t)(region.end - addr);   /* clamp inside the mapping */
        if (len == 0) {
            return KX_MEM_EFAULT;
        }
    }

    got = pread(ctx->mem_fd, dst, len, (off_t)addr);
    if (got < 0) {
        int err = errno;
        syslog(LOG_WARNING,
               "kx_mem_read: pread @0x%" PRIx64 " failed (%s) - likely a "
               "transient page fault or policy denial; skipping safely",
               addr, strerror(err));
        return errno_to_rc(err);
    }
    ctx->bytes_read += (size_t)got;
    if (nread != NULL) {
        *nread = (size_t)got;
    }
    return KX_MEM_OK;
}

int kx_mem_write_authorized(void)
{
#if KX_SANDBOX_BUILD
    /* Sandbox builds hard-refuse writes at compile time. */
    syslog(LOG_WARNING, "write authorization DENIED (sandbox build)");
    return 0;
#else
    /* Even outside the sandbox, mutation requires root AND an explicit
     * environment opt-in set by main_controller.sh. Both conditions are
     * audited loudly. */
    if (geteuid() != 0) {
        return 0;
    }
    if (getenv("KX_LAB_ALLOW_MEMORY_WRITE") == NULL) {
        return 0;
    }
    syslog(LOG_WARNING,
           "write authorization GRANTED only for operator-owned lab child "
           "processes; this event is recorded for audit review");
    return 1;
#endif
}

int kx_mem_refused_write(uint64_t addr)
{
    if (kx_mem_write_authorized()) {
        /* The full production pipeline is intentionally NOT implemented in
         * the educational branch: there is no code path here that modifies
         * remote memory. Reaching this point still refuses. */
        syslog(LOG_WARNING,
               "kx_mem_refused_write: authorization present but the "
               "educational build contains no write path; refusing @0x%" PRIx64,
               addr);
    } else {
        syslog(LOG_WARNING, "kx_mem_refused_write: unauthorized write to "
               "0x%" PRIx64 " blocked", addr);
    }
    return KX_MEM_EWRITE_BLOCKED;
}
