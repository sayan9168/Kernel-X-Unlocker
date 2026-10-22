/* memory_utils.h - Safe, read-only process-memory inspection helpers.
 *
 * Kernel-X Research Toolkit (lab/educational build).
 *
 * DESIGN RULES enforced by this header:
 *   1. Every accessor is READ-ONLY. There is no usable write API in this
 *      module; a future write path would have to pass an explicit
 *      authorization check (kx_mem_write_authorized()) AND only ever target
 *      a process the operator owns.
 *   2. All addresses are validated against /proc/<pid>/maps before use so
 *      invalid pointers degrade to errors instead of SIGSEGV-ing the tool
 *      or disturbing the target.
 *   3. Every syscall result is checked; EPERM/EACCES are reported as
 *      "expected Android SELinux denial" rather than retried aggressively.
 */
#ifndef KX_MEMORY_UTILS_H
#define KX_MEMORY_UTILS_H

/* Feature tests: expose POSIX/GNU declarations (pread, O_CLOEXEC, ...) even
 * when the translation unit is compiled with strict -std=c11. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Region descriptor parsed from /proc/<pid>/maps ---------------------- */
typedef struct kx_mem_region {
    uint64_t start;
    uint64_t end;
    int readable;
    int writable;
    int executable;
    char path[256];
} kx_mem_region_t;

/* ---- Memory context for one target process ------------------------------- */
typedef struct kx_mem_ctx {
    pid_t pid;
    int mem_fd;           /* O_RDONLY only. The kernel refuses cross-process
                           * writes here without ptrace attach, which this
                           * toolkit deliberately never performs. */
    size_t max_read_bytes;/* global budget, prevents runaway scanning */
    size_t bytes_read;
} kx_mem_ctx_t;

/* Return codes */
#define KX_MEM_OK              0
#define KX_MEM_EINVAL         (-1)
#define KX_MEM_EPERM          (-2)   /* permission denied (SELinux/Yama) */
#define KX_MEM_ENOENT         (-3)   /* no such pid / region */
#define KX_MEM_EFAULT         (-4)   /* bad address / unmapped page */
#define KX_MEM_EBUDGET        (-5)   /* scan budget exhausted */
#define KX_MEM_EWRITE_BLOCKED (-6)   /* write attempted without authorization */

/* Open a read-only context on target_pid. Returns NULL on any failure with
 * errno preserved and a syslog note emitted. Never attaches with ptrace. */
kx_mem_ctx_t *kx_mem_open(pid_t target_pid, size_t max_read_bytes);

/* Close context; idempotent, safe with NULL. */
void kx_mem_close(kx_mem_ctx_t *ctx);

/* Look up the mapping containing `addr`. Fills out_region when found.
 * Returns KX_MEM_OK / KX_MEM_ENOENT (unmapped) / KX_MEM_EPERM. */
int kx_mem_validate_addr(kx_mem_ctx_t *ctx, uint64_t addr,
                         kx_mem_region_t *out_region);

/* Read up to len bytes at addr into dst (bounded by ctx budget). Uses pread()
 * so there are no lseek races; faults on unmapped pages return KX_MEM_EFAULT
 * with *nread set to 0. */
int kx_mem_read(kx_mem_ctx_t *ctx, uint64_t addr, void *dst, size_t len,
                size_t *nread);

/* Authorization gate for any hypothetical mutation path. In sandbox/dry-run
 * builds this ALWAYS returns 0 (denied). A write may only proceed when ALL
 * of the following hold (checked by the implementation):
 *   - config flag allow_memory_write == true (explicit operator opt-in)
 *   - dry_run == false
 *   - euid == 0 AND running under the controller sandbox profile
 * This is intentionally hard to satisfy and logged loudly when it does. */
int kx_mem_write_authorized(void);

/* Attempted-write stub: logs and refuses unless fully authorized. Present so
 * the call graph documents that writes are blocked, not forgotten. */
int kx_mem_refused_write(uint64_t addr);

#ifdef __cplusplus
}
#endif

#endif /* KX_MEMORY_UTILS_H */
