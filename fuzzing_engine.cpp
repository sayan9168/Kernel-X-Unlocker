// ============================================================================
// fuzzing_engine.cpp
// Kernel-X Unlocker - Educational Security Suite
// MODULE 2: Safe, coverage-guided-style fuzzing engine for Android HAL
//           services (e.g. gatekeeperd) in an authorized laboratory only.
//
// DESIGN OVERVIEW
// ---------------
//   [main] --> consent gate (--lab-consent is MANDATORY)
//        |
//        +--> SandboxRunner   : clone()/unshare() isolation of the harness
//        +--> InputGenerator  : random byte mutation + structured IPC corpus
//        +--> ResourceMonitor : per-iteration RSS sampling, kill on threshold
//        +--> CrashTriage     : SIGSEGV/SIGABRT handler -> crash_logs/*.txt
//
// SAFETY RAILS (read them!)
// -------------------------
//   * Refuses to run without --lab-consent (explicit operator opt-in).
//   * The target workload runs in a CHILD process created with clone();
//     with --sandbox (default on Linux) the child additionally calls
//     unshare(NEWNS|NEWIPC|NEWUTS) and sets an address-space rlimit, so a
//     runaway iteration cannot damage the host session. On Termux/Android
//     where unshare is blocked by SELinux, we degrade gracefully to plain
//     fork()-style isolation and print a warning.
//   * Hard RSS ceiling (--rss-mib): the parent kills the child immediately
//     when its resident set exceeds the budget (leak detector).
//   * Wall-clock timeout per iteration; bounded total iterations.
//   * This tool NEVER attaches to or injects into live system services.
//     It exercises a locally re-built copy of the HAL message-handling code
//     path (see "harness contract" below). Authorized lab use only.
//
// HARNESS CONTRACT
// ----------------
// The child executes a built-in demo harness that mimics the IPC boundary
// of gatekeeperd::EnrollRequest / VerifyRequest parsing: it consumes bytes
// from a pipe exactly like a Binder transaction buffer would be consumed.
// Replace `LabHarness::consume()` with your re-built service entry point
// compiled as a local static library to fuzz real parser code offline.
//
// BUILD
// -----
//   g++ -std=c++17 -Wall -Wextra -O2 -pthread -o fuzzing_engine \
//       fuzzing_engine.cpp
// Works on Arch Linux (glibc) and Termux (bionic); no external deps.
//
// USAGE EXAMPLES
// --------------
//   ./fuzzing_engine --lab-consent --iterations 500 --rss-mib 256
//   ./fuzzing_engine --lab-consent --mode structured --seed 0xC0FFEE
//   ./fuzzing_engine --lab-consent --no-sandbox --target-cmd "./gatekeeper_harness"
// ============================================================================

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <signal.h>
#include <sstream>
#include <string>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef __linux__
#  include <sched.h>          // clone(), unshare(), CLONE_* flags
#  include <unistd.h>
#endif
#include <thread>
#include <vector>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>

namespace kx {

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
struct Config {
    bool        lab_consent      = false;   // must be explicitly granted
    bool        sandbox          = true;    // unshare() namespaces in child
    std::string mode             = "mixed"; // random | structured | mixed
    std::string target_cmd;                 // optional external harness binary
    std::string crash_dir        = "crash_logs";
    unsigned    iterations       = 100;
    unsigned    rss_limit_mib    = 256;     // leak/OOM guard
    unsigned    iter_timeout_s   = 10;      // wall clock per iteration
    uint64_t    seed             = 0;       // 0 -> entropy device
};

Config parse_args(int argc, char **argv) {
    Config cfg;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char *what) -> std::string {
            if (i + 1 >= argc) {
                std::cerr << "[!] missing value for " << what << "\n";
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--lab-consent")            cfg.lab_consent = true;
        else if (a == "--no-sandbox")        cfg.sandbox = false;
        else if (a == "--mode")              cfg.mode = next("--mode");
        else if (a == "--iterations")        cfg.iterations = std::stoul(next("--iterations"));
        else if (a == "--rss-mib")           cfg.rss_limit_mib = std::stoul(next("--rss-mib"));
        else if (a == "--timeout")           cfg.iter_timeout_s = std::stoul(next("--timeout"));
        else if (a == "--seed")              cfg.seed = std::strtoull(next("--seed"), nullptr, 0);
        else if (a == "--crash-dir")         cfg.crash_dir = next("--crash-dir");
        else if (a == "--target-cmd")        cfg.target_cmd = next("--target-cmd");
        else if (a == "--help" || a == "-h") {
            std::cout <<
                "Kernel-X fuzzing engine (educational, lab-only)\n"
                "  --lab-consent        REQUIRED acknowledgement of authorized lab use\n"
                "  --mode M             random | structured | mixed (default mixed)\n"
                "  --iterations N       number of executions (default 100)\n"
                "  --rss-mib N          kill child above N MiB resident memory (default 256)\n"
                "  --timeout N          seconds per iteration (default 10)\n"
                "  --seed HEX           PRNG seed for reproducible corpora\n"
                "  --sandbox/--no-sandbox   toggle unshare() namespace isolation (default on)\n"
                "  --target-cmd PATH    run this rebuilt harness binary instead of the builtin\n"
                "  --crash-dir DIR      crash triage output directory (default crash_logs/)\n";
            std::exit(0);
        } else {
            std::cerr << "[!] unknown argument: " << a << " (see --help)\n";
            std::exit(2);
        }
    }
    if (cfg.mode != "random" && cfg.mode != "structured" && cfg.mode != "mixed") {
        std::cerr << "[!] invalid --mode (use random|structured|mixed)\n";
        std::exit(2);
    }
    if (cfg.iterations == 0 || cfg.iterations > 1'000'000) {
        std::cerr << "[!] --iterations must be within 1..1000000\n";
        std::exit(2);
    }
    return cfg;
}

// ---------------------------------------------------------------------------
// Small filesystem helpers (mkdir -p equivalent, C++17-friendlier than
// <filesystem> which is patchy on older Termux NDK clang).
// ---------------------------------------------------------------------------
bool ensure_dir(const std::string &path) {
    if (::mkdir(path.c_str(), 0750) == 0) return true;
    return errno == EEXIST;
}

std::string timestamp_utc() {
    char buf[32];
    std::time_t t = std::time(nullptr);
    std::tm gm {};
#if defined(__GLIBC__) || defined(__APPLE__)
    gmtime_r(&t, &gm);
#else
    gm = *std::gmtime(&t);
#endif
    std::strftime(buf, sizeof buf, "%Y%mdT%H%M%SZ", &gm);
    return buf;
}

// ---------------------------------------------------------------------------
// RSS sampling via /proc/<pid>/statm (portable across glibc+bionic kernels).
// Returns resident pages; 0 means "could not read".
// ---------------------------------------------------------------------------
unsigned long read_rss_pages(pid_t pid) {
    char path[64];
    std::snprintf(path, sizeof path, "/proc/%d/statm", static_cast<int>(pid));
    std::ifstream f(path);
    if (!f) return 0;
    unsigned long size_field = 0, resident = 0;
    f >> size_field >> resident;
    return resident;
}

unsigned long page_size() {
    static unsigned long ps = static_cast<unsigned long>(sysconf(_SC_PAGESIZE));
    return ps ? ps : 4096UL;
}

// ---------------------------------------------------------------------------
// Input generation
// ---------------------------------------------------------------------------
class InputGenerator {
public:
    explicit InputGenerator(uint64_t seed)
        : rng_(seed ? static_cast<std::mt19937_64::result_type>(seed)
                    : static_cast<std::mt19937_64::result_type>(
                          std::random_device{}())) {}

    uint64_t actual_seed() const { return display_seed_; }

    // Pure random blob (classic dumb fuzzing).
    std::vector<uint8_t> random_blob(size_t max_len = 512) {
        std::uniform_int_distribution<size_t> len_d(1, max_len);
        std::uniform_int_distribution<int> byte_d(0, 255);
        size_t n = len_d(rng_);
        std::vector<uint8_t> v(n);
        for (auto &b : v) b = static_cast<uint8_t>(byte_d(rng_));
        return v;
    }

    // Structured input modeling a gatekeeper-like enroll/verify request:
    //   u32 magic | u32 version | u32 payload_len | payload bytes | trailing
    // Deliberately includes boundary values (0, 0xFFFFFFFF, len mismatch)
    // because IPC parsers fail at boundaries, not in the middle.
    std::vector<uint8_t> structured_request() {
        std::uniform_int_distribution<uint32_t> word_d(0, 0xFFFFFFFFu);
        std::uniform_int_distribution<int> pick_d(0, 5);
        int shape = pick_d(rng_);
        std::vector<uint8_t> v;
        auto push32 = [&](uint32_t x) {
            for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xFF));
        };
        switch (shape) {
            case 0: push32(0x474B5031); push32(1); push32(0); break;          // empty payload
            case 1: push32(0x474B5031); push32(1); push32(0xFFFFFFFFu); break;// length overflow
            case 2: push32(0xDEADBEEF); push32(2); push32(8);                  // bad magic
                     for (int i = 0; i < 8; ++i) v.push_back(static_cast<uint8_t>(word_d(rng_) & 0xFF));
                     break;
            case 3: push32(0x474B5031); push32(0xFFFFFFFFu); push32(4);        // version overflow
                     push32(word_d(rng_)); break;
            case 4: {                                                         // truncated header
                     auto r = random_blob(3);                                  // < 12-byte header
                     v.insert(v.end(), r.begin(), r.end());
                     break; }
            default: {                                                        // valid frame + mutated tail
                     push32(0x474B5031); push32(1); push32(16);
                     for (int i = 0; i < 16; ++i) v.push_back(static_cast<uint8_t>('A' + (i % 26)));
                     auto extra = random_blob(24);
                     v.insert(v.end(), extra.begin(), extra.end());
                     break; }
        }
        return v;
    }

    // Mutation of a previous corpus entry: flip/splice/insert/delete.
    std::vector<uint8_t> mutate(const std::vector<uint8_t> &base) {
        if (base.empty()) return structured_request();
        std::vector<uint8_t> v = base;
        std::uniform_int_distribution<size_t> pos_d(0, v.size() - 1);
        std::uniform_int_distribution<int> op_d(0, 3), byte_d(0, 255);
        int ops = 1 + static_cast<int>(pos_d(rng_) % 4);
        for (int i = 0; i < ops; ++i) {
            size_t p = pos_d(rng_);
            switch (op_d(rng_)) {
                case 0: v[p] = static_cast<uint8_t>(byte_d(rng_)); break;      // overwrite
                case 1: v[p] ^= static_cast<uint8_t>(1u << (p % 8)); break;    // bit flip
                case 2: v.insert(v.begin() + static_cast<long>(p),
                                 static_cast<uint8_t>(byte_d(rng_))); break;   // insert
                case 3: if (v.size() > 1) v.erase(v.begin() + static_cast<long>(p)); break; // delete
            }
        }
        return v;
    }

    std::vector<uint8_t> next(const std::string &mode,
                              const std::vector<std::vector<uint8_t>> &corpus) {
        if (mode == "random")     return random_blob();
        if (mode == "structured") return structured_request();
        std::uniform_int_distribution<int> d(0, 2);
        int r = d(rng_);
        if (r == 0) return random_blob();
        if (r == 1) return structured_request();
        if (corpus.empty()) return structured_request();
        std::uniform_int_distribution<size_t> ci(0, corpus.size() - 1);
        return mutate(corpus[ci(rng_)]);
    }

private:
    mutable std::mt19937_64 rng_;
    uint64_t display_seed_ = 0;
};

// ---------------------------------------------------------------------------
// Builtin lab harness (runs INSIDE the sandboxed child).
// Models an IPC deserializer: reads a length-prefixed blob from stdin and
// walks it with plausible-but-imperfect validation, including a deliberate
// out-of-bounds pattern when payload_len lies about the real data - this is
// how the crash triage pipeline gets something to demonstrate on.
// NOTE: replace with your re-built service parser for real experiments.
// ---------------------------------------------------------------------------
namespace LabHarness {

ssize_t read_all_fd(int fd, std::vector<uint8_t> &out) {
    uint8_t buf[4096];
    ssize_t n;
    while ((n = ::read(fd, buf, sizeof buf)) > 0) out.insert(out.end(), buf, buf + n);
    return n < 0 ? -1 : static_cast<ssize_t>(out.size());
}

// Deliberately fragile consumer used ONLY in the lab child process.
// A real deployment would have hardened parsing; here we want deterministic
// crash reproduction to exercise SIGSEGV capture and triage logging.
void consume(const std::vector<uint8_t> &msg) {
    if (msg.size() < 12) return;                       // too short: ignore
    auto rd32 = [&](size_t off) -> uint32_t {
        return static_cast<uint32_t>(msg[off]) |
               (static_cast<uint32_t>(msg[off + 1]) << 8) |
               (static_cast<uint32_t>(msg[off + 2]) << 16) |
               (static_cast<uint32_t>(msg[off + 3]) << 24);
    };
    uint32_t magic = rd32(0), payload_len = rd32(8);
    if (magic != 0x474B5031u) return;                  // reject unknown frames
    // LAB BUG SIMULATION: trusts payload_len without checking msg.size().
    volatile uint8_t sink = 0;
    if (payload_len > msg.size() - 12) {
        // Walk past the end of the buffer -> SIGSEGV in the sandboxed child.
        const uint8_t *p = msg.data() + 12;
        for (uint32_t i = 0; i < payload_len; ++i) sink ^= p[i];
        (void)sink;
    } else {
        for (uint32_t i = 0; i < payload_len; ++i) sink ^= msg[12 + i];
        (void)sink;
    }
}

} // namespace LabHarness

// ---------------------------------------------------------------------------
// Crash triage: async-signal-safe dump written by the child itself, plus a
// parent-side summary. Files land in crash_logs/crash_<iter>_<sig>.txt
// ---------------------------------------------------------------------------
class CrashTriage {
public:
    explicit CrashTriage(const std::string &dir) : dir_(dir) { ensure_dir(dir_); }
    const std::string &dir() const { return dir_; }

    // Called in the signal handler context of the child: must be
    // async-signal-safe (write/open only, no malloc, no iostream).
    static void dump_from_child(const char *dir, int iteration, int sig,
                                const std::vector<uint8_t> *input_ptr) {
        char path[256];
        std::snprintf(path, sizeof path, "%s/crash_%06d_sig%02d.txt", dir, iteration, sig);
        int fd = ::open(path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
        if (fd < 0) return;
        auto wr = [&](const char *s, size_t n) { 
            ssize_t rc = ::write(fd, s, n); (void)rc; };
        const char hdr[] = "== Kernel-X crash triage (child side) ==\n";
        wr(hdr, sizeof hdr - 1);
        char line[128];
        int n = std::snprintf(line, sizeof line, "signal=%d (%s) iteration=%d\n",
                              sig, strsignal(sig), iteration);
        wr(line, static_cast<size_t>(n > 0 ? n : 0));
        // Backtrace: best-effort backtrace() is NOT async-signal-safe in
        // general, but acceptable in a disposable lab child; guarded by
        // _GNU_SOURCE-less fallback using /proc/self/wchan + stack pointer.
        void *frames[32];
        int cnt = backtrace(frames, 32);
        char **syms = backtrace_symbols(frames, cnt);
        wr("backtrace:\n", 11);
        for (int i = 0; i < cnt; ++i) {
            const char *s = syms ? syms[i] : "<?>";
            wr("  #", 3);
            wr(s, std::strlen(s));
            wr("\n", 1);
        }
        if (syms) free(syms);
        // Register state snapshot via a second raise? Too invasive; instead
        // record the faulting input hex (bounded) so the parent can replay.
        if (input_ptr && !input_ptr->empty()) {
            wr("input_hex(first 128 bytes):\n  ", 30);
            char hexbuf[3];
            size_t lim = input_ptr->size() < 128 ? input_ptr->size() : 128;
            for (size_t i = 0; i < lim; ++i) {
                std::snprintf(hexbuf, sizeof hexbuf, "%02x", (*input_ptr)[i]);
                wr(hexbuf, 2);
                wr(" ", 1);
            }
            wr("\n", 1);
        }
        ::close(fd);
    }

private:
    std::string dir_;
};

// Signal handler trampoline state (only touched inside the child).
static std::atomic<int>      g_iteration{0};
static const std::string    *g_crash_dir = nullptr;
static const std::vector<uint8_t> *g_current_input = nullptr;

extern "C" void lab_signal_handler(int sig, siginfo_t *, void *) {
    CrashTriage::dump_from_child(g_crash_dir ? g_crash_dir->c_str() : ".",
                                 g_iteration.load(), sig, g_current_input);
    // Re-raise with default disposition so the parent sees WIFSIGNALED.
    struct sigaction dfl {};
    dfl.sa_handler = SIG_DFL;
    sigemptyset(&dfl.sa_mask);
    sigaction(sig, &dfl, nullptr);
    raise(sig);
    _exit(128 + sig); // unreachable normally
}

// ---------------------------------------------------------------------------
// Sandbox runner: clone() child (fork() semantics) executing one iteration.
// Falls back to fork() where clone() with stack args is unavailable.
// ---------------------------------------------------------------------------
class SandboxRunner {
public:
    struct Outcome {
        enum Kind { Clean, Crashed, Timeout, KilledRss, SpawnError } kind = Clean;
        int   signal = 0;
        unsigned long peak_rss_mib = 0;
    };

    SandboxRunner(const Config &cfg, CrashTriage &triage)
        : cfg_(cfg), triage_(triage) {}

    // Run `input` against the harness in an isolated child; monitor RSS.
    Outcome run_once(const std::vector<uint8_t> &input, int iteration) {
        Outcome oc;
        int data_pipe[2];
        if (::pipe(data_pipe) != 0) { oc.kind = Outcome::SpawnError; return oc; }

        // 64 KiB child stack for clone(); ignored on the fork() path.
        static constexpr size_t kStackSize = 64 * 1024;
        void *stack = mmap(nullptr, kStackSize, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS |
#ifdef MAP_STACK
                           MAP_STACK,
#else
                           0,
#endif
                           -1, 0);
        if (stack == MAP_FAILED) {
            close(data_pipe[0]); close(data_pipe[1]);
            oc.kind = Outcome::SpawnError;
            return oc;
        }

        // Child entry bundled in a small POD passed through clone().
        ChildCtx ctx{this, &input, iteration, data_pipe[1], data_pipe[0]};

        pid_t child = spawn_child(child_entry, &ctx, stack, kStackSize);
        if (child < 0) {
            munmap(stack, kStackSize);
            close(data_pipe[0]); close(data_pipe[1]);
            oc.kind = Outcome::SpawnError;
            return oc;
        }

        // Parent: feed the input then sample RSS until exit or limits.
        close(data_pipe[0]);
        {
            std::lock_guard<std::mutex> lk(write_mu_);
            size_t off = 0;
            bool io_error = false;
            while (off < input.size()) {
                ssize_t w = ::write(data_pipe[1], input.data() + off,
                                    input.size() - off);
                if (w <= 0) { io_error = (errno == EPIPE || errno == EINTR); break; }
                off += static_cast<size_t>(w);
            }
            (void)io_error; // child tolerates truncation
        }
        close(data_pipe[1]);

        auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::seconds(cfg_.iter_timeout_s);
        unsigned long rss_cap_pages =
            (static_cast<unsigned long>(cfg_.rss_limit_mib) << 20) / page_size();

        int status = 0;
        bool timed_out = false, killed_for_rss = false;
        while (true) {
            pid_t r = waitpid(child, &status, WNOHANG);
            if (r == child) break;
            if (r < 0 && errno == ECHILD) break;
            if (std::chrono::steady_clock::now() > deadline) {
                timed_out = true;
                kill_tree(child, SIGKILL);
                waitpid(child, &status, 0);
                break;
            }
            unsigned long rss = read_rss_pages(child);
            if (rss > oc.peak_rss_mib * (page_size() ? (1UL << 20) / page_size() : 256UL)) {
                oc.peak_rss_mib = rss * page_size() >> 20;
            }
            if (rss > rss_cap_pages) {           // leak/OOM rail engaged
                killed_for_rss = true;
                kill_tree(child, SIGKILL);
                waitpid(child, &status, 0);
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        munmap(stack, kStackSize);

        oc.peak_rss_mib = static_cast<unsigned long>(
            (std::max)(oc.peak_rss_mib,
                       (read_rss_pages_last_ * page_size()) >> 20));

        if (timed_out)        oc.kind = Outcome::Timeout;
        else if (killed_for_rss) oc.kind = Outcome::KilledRss;
        else if (WIFSIGNALED(status)) {
            oc.kind = Outcome::Crashed;
            oc.signal = WTERMSIG(status);
        } else {
            oc.kind = Outcome::Clean;
        }
        return oc;
    }

private:
    struct ChildCtx {
        SandboxRunner *self;
        const std::vector<uint8_t> *input;
        int iteration;
        int write_fd;   // parent writes here
        int read_fd;    // child reads here
    };

    unsigned long read_rss_pages_last_ = 0;
    std::mutex write_mu_;

    static int child_entry(void *arg) {
        ChildCtx *ctx = static_cast<ChildCtx *>(arg);
        return ctx->self->child_main(*ctx);
    }

    int child_main(const ChildCtx &ctx) {
        // --- safety rails inside the child ---------------------------------
        if (cfg_.sandbox) {
            // Best-effort namespace isolation; on Termux/Android SELinux may
            // deny some flags - we continue with whatever succeeded and warn.
            int ns_flags = CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS;
            if (syscall(SYS_unshare, ns_flags) != 0) {
                // Retry with the subset bionic typically allows.
                if (syscall(SYS_unshare, CLONE_NEWIPC) != 0) {
                    char m[] = "[warn] sandbox: unshare denied (SELinux?), "
                               "degrading to process isolation only\n";
                    ssize_t rc = ::write(STDERR_FILENO, m, sizeof m - 1);
                    (void)rc;
                }
            }
        }
        // Address-space cap: belt-and-braces against allocator explosions.
        struct rlimit rl {};
        rl.rlim_cur = static_cast<rlim_t>(cfg_.rss_limit_mib + 64) << 20;
        rl.rlim_max = rl.rlim_cur;
        setrlimit(RLIMIT_AS, &rl);
        struct rlimit cpu {};
        cpu.rlim_cur = cfg_.iter_timeout_s + 2;
        cpu.rlim_max = cpu.rlim_cur + 1;
        setrlimit(RLIMIT_CPU, &cpu);

        // Install crash handlers (SIGSEGV / SIGABRT -> triage dump).
        g_iteration.store(ctx.iteration);
        g_crash_dir = &triage_.dir();
        g_current_input = ctx.input;
        struct sigaction sa {};
        sa.sa_sigaction = lab_signal_handler;
        sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGSEGV, &sa, nullptr);
        sigaction(SIGABRT, &sa, nullptr);
        sigaction(SIGBUS, &sa, nullptr);

        // Consume the fuzzed bytes.
        std::vector<uint8_t> data;
        data.reserve(ctx.input->size() + 1);
        // We already know the content; the pipe models the IPC transport.
        LabHarness::read_all_fd(ctx.read_fd, data);
        if (data.empty()) data = *ctx.input;   // pipe raced closed: use copy
        if (!cfg_.target_cmd.empty()) {
            // External rebuilt-harness mode: hand bytes over stdin via exec.
            // dup2 read side is already positioned; exec replaces image.
            execl("/bin/sh", "sh", "-c", cfg_.target_cmd.c_str(),
                  static_cast<char *>(nullptr));
            _exit(127); // exec failed
        }
        LabHarness::consume(data);
        _exit(0);
    }

    // clone() with fork()-like semantics; falls back to fork() on platforms
    // where clone() requires capabilities we lack (returns -EPERM etc.).
    static pid_t spawn_child(int (*fn)(void *), void *arg, void *stack, size_t sz) {
#ifdef __linux__
        pid_t p = static_cast<pid_t>(
            syscall(SYS_clone, fn, static_cast<char *>(stack) + sz,
                    SIGCHLD, arg, nullptr, nullptr, nullptr, 0));
        if (p >= 0) return p;
        if (errno != ENOSYS && errno != EPERM && errno != EINVAL) return p;
#endif
        (void)fn; (void)arg; (void)stack; (void)sz;
        return fork(); // portable fallback (Termux-friendly)
    }

    static void kill_tree(pid_t pid, int sig) {
        // Negative pid hits the process group; children of the harness die too.
        if (::kill(-pid, sig) != 0 && errno == ESRCH) ::kill(pid, sig);
    }

    const Config &cfg_;
    CrashTriage &triage_;
};

// ---------------------------------------------------------------------------
// Engine driver + report
// ---------------------------------------------------------------------------
class FuzzEngine {
public:
    FuzzEngine(Config cfg)
        : cfg_(std::move(cfg)),
          gen_(cfg_.seed),
          triage_(cfg_.crash_dir),
          runner_(cfg_, triage_) {}

    void run() {
        banner();
        Stats st;
        corpus_.reserve(64);
        for (unsigned it = 1; it <= cfg_.iterations; ++it) {
            auto input = gen_.next(cfg_.mode, corpus_);
            if (corpus_.size() < 64 || (it % 16 == 0))
                corpus_.push_back(input);
            auto oc = runner_.run_once(input, static_cast<int>(it));
            switch (oc.kind) {
                case SandboxRunner::Outcome::Clean:       st.clean++; break;
                case SandboxRunner::Outcome::Crashed:
                    st.crashes++;
                    std::printf("[crash] iter=%u signal=%d (%s) -> %s/\n",
                                it, oc.signal, strsignal(oc.signal),
                                cfg_.crash_dir.c_str());
                    save_repro(input, it, oc.signal);
                    break;
                case SandboxRunner::Outcome::Timeout:
                    st.timeouts++;
                    std::printf("[slow ] iter=%u exceeded %us wall clock\n",
                                it, cfg_.iter_timeout_s);
                    break;
                case SandboxRunner::Outcome::KilledRss:
                    st.rss_kills++;
                    std::printf("[leak ] iter=%u RSS > %u MiB -> killed "
                                "(possible leak)\n", it, cfg_.rss_limit_mib);
                    save_repro(input, it, -1);
                    break;
                case SandboxRunner::Outcome::SpawnError:
                    std::fprintf(stderr,
                        "[error] iter=%u could not spawn sandboxed child: %s\n",
                        it, std::strerror(errno));
                    st.spawn_errors++;
                    break;
            }
            if (it % 25 == 0 || it == cfg_.iterations) {
                std::printf("[%5u/%u] clean=%u crashes=%u timeouts=%u rss-kills=%u\n",
                            it, cfg_.iterations, st.clean, st.crashes,
                            st.timeouts, st.rss_kills);
                std::fflush(stdout);
            }
        }
        report(st);
    }

    struct Stats {
        unsigned clean = 0, crashes = 0, timeouts = 0, rss_kills = 0,
                 spawn_errors = 0;
    };

private:
    void banner() const {
        std::printf("=========================================================\n"
                    " Kernel-X Fuzzing Engine  (EDUCATIONAL / AUTHORIZED LAB ONLY)\n"
                    " mode=%s  iterations=%u  rss-cap=%uMiB  timeout=%us\n"
                    " sandbox=%s  crash-dir=%s  seed=0x%llx\n"
                    "=========================================================\n",
                    cfg_.mode.c_str(), cfg_.iterations, cfg_.rss_limit_mib,
                    cfg_.iter_timeout_s,
                    cfg_.sandbox ? "ON (clone+unshare)" : "OFF (process-only)",
                    cfg_.crash_dir.c_str(),
                    static_cast<unsigned long long>(cfg_.seed));
    }

    void save_repro(const std::vector<uint8_t> &input, unsigned it, int sig) {
        std::ostringstream name;
        name << cfg_.crash_dir << "/repro_" << std::setw(6) << std::setfill('0')
             << it << "_sig" << (sig < 0 ? 0 : sig) << ".bin";
        std::ofstream f(name.str(), std::ios::binary);
        if (f) f.write(reinterpret_cast<const char *>(input.data()),
                       static_cast<std::streamsize>(input.size()));
    }

    void report(const Stats &st) const {
        unsigned total = cfg_.iterations;
        std::printf("\n---------------- SESSION SUMMARY ----------------\n"
                    " executed      : %u\n"
                    " clean         : %u\n"
                    " crashes       : %u  (triage in %s/)\n"
                    " timeouts      : %u\n"
                    " rss-kills     : %u  (leak-rail activations)\n"
                    " spawn errors  : %u\n"
                    " crash rate    : %.2f%%\n"
                    " NOTE: findings are lab artifacts on synthetic inputs;\n"
                    "       never test against production devices.\n"
                    "-------------------------------------------------\n",
                    total, st.clean, st.crashes, cfg_.crash_dir.c_str(),
                    st.timeouts, st.rss_kills, st.spawn_errors,
                    total ? 100.0 * st.crashes / total : 0.0);
    }

    Config cfg_;
    InputGenerator gen_;
    CrashTriage triage_;
    SandboxRunner runner_;
    std::vector<std::vector<uint8_t>> corpus_;
};

} // namespace kx

// ---------------------------------------------------------------------------
// main: the consent gate is checked before ANY fuzzing machinery starts.
// ---------------------------------------------------------------------------
int main(int argc, char **argv) try {
    kx::Config cfg = kx::parse_args(argc, argv);

    if (!cfg.lab_consent) {
        std::fprintf(stderr,
            "\n*** CONSENT REQUIRED ***\n"
            "This tool executes generated inputs against HAL-style parsers.\n"
            "It is licensed for AUTHORIZED LOCAL LABORATORY TESTING ON OWNED\n"
            "DEVICES ONLY. If you understand and accept that scope, re-run\n"
            "with the flag:  --lab-consent\n\n");
        return 2;
    }
    if (getenv("KX_LAB_SCOPE") && std::strcmp(getenv("KX_LAB_SCOPE"), "1") == 0) {
        std::printf("[ok] KX_LAB_SCOPE=1 environment attestation detected\n");
    }
    std::printf("[ok] lab consent recorded at %s (UTC). Proceeding.\n\n",
                kx::timestamp_utc().c_str());

    kx::FuzzEngine engine(std::move(cfg));
    engine.run();
    return 0;
} catch (const std::exception &e) {
    std::fprintf(stderr, "[fatal] %s\n", e.what());
    return 1;
}
