// A LLC-slice-aware memory performance attacker, which targets a single LLC slice (CHA)
//
// Author: Heechul Yun (heechul.yun@ku.edu)
//
// Approach: Uses Intel uncore CHA perf counters with NT-store bursts
// (same technique as slicemap.c) to identify which LLC slice each
// cache-line-aligned address maps to, then collects addresses belonging
// to a target slice and hammers them.
//
// Compile:
//    g++ -O2 -std=c++17 -o oneslice_attacker oneslice_attacker.cpp -lpthread
// Usage:
//   $ sudo ./oneslice_attacker --base 0x1c --event 0xf50 --slices 40 \
//          --target-slice 0 -k 500 -m 4096 -a write -n 4
// Note:
//   Must run as root (perf_event_open for uncore events).
//   Adjust --base, --event, --slices for your platform.


#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <map>
#include <list>
#include <set>
#include <algorithm>
#include <sys/time.h>
#include <math.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <vector>
#include <random>
#include <array>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <getopt.h>
#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#endif

// ------------ NT-store burst macros (from slicemap.c) ----------------
#define REP4(x)   x x x x
#define REP16(x)  REP4(x)  REP4(x)  REP4(x)  REP4(x)
#define REP256(x) REP16(x) REP16(x) REP16(x) REP16(x) \
                  REP16(x) REP16(x) REP16(x) REP16(x)  \
                  REP16(x) REP16(x) REP16(x) REP16(x)  \
                  REP16(x) REP16(x) REP16(x) REP16(x)
#define REP1K(x)  REP256(x) REP256(x) REP256(x) REP256(x)
#define REP4K(x)  REP1K(x)  REP1K(x)  REP1K(x)  REP1K(x)

#define NT_STORE(addr) \
    asm volatile("movnti %1, (%0)\n\t" "sfence\n\t" \
                 : : "r"(addr), "r"((uint64_t)0xdeadbeefULL) : "memory")

#define MAX_SLICES   256
#define MIN_SIGNAL   2000   /* minimum CHA count to trust a measurement */

// ------------ global settings ----------------
int verbosity = 1;
size_t g_page_size;

int g_access_type = 0; // 0: read, 1: write
int g_cache_mode = 1; // 0: normal cached access, 1: 0 + clflushopt/clwb, 2: 0 + clflush, 3: non-temporal ld/st

size_t mapping_size = (1ULL<<30); // 1GB default
volatile int g_quit_signal = 0;

// Slice discovery parameters
int g_nslices    = -1;    // number of CHA slices
int g_base_type  = -1;    // perf base type for uncore_cha_0
uint64_t g_event_cfg = 0; // perf event config
int g_target_slice = 0;   // which slice to attack
int g_target_n   = 500;   // target number of addresses to collect
// ----------------------------------------------

typedef uint64_t pointer;

#define logError(f, ...) do { printf("[%-9s] ", "ERROR"); printf(f, __VA_ARGS__); } while(0);
#define logWarning(f, ...) do { if(verbosity > 0) {printf("[%-9s] ", "WARNING"); printf(f, __VA_ARGS__);} } while(0);
#define logInfo(f, ...) do { if(verbosity > 1) {printf("[%-9s] ", "INFO"); printf(f, __VA_ARGS__); }} while(0);
#define logLog(f, ...) do { if(verbosity > 2) {printf("[%-9s] ", "LOG"); printf(f, __VA_ARGS__); }} while(0);
#define logDebug(f, ...) do { if(verbosity > 3) {printf("[%-9s] ", "DEBUG"); printf(f, __VA_ARGS__); }} while(0);

#define printBinary(x) do { std::bitset<sizeof(size_t) * 8> bs(x); std::cout << bs; } while(0);

// ----------------------------------------------

#define MAX_HIST_SIZE 2000

std::vector <std::vector<pointer>> sets; // discovered sets

void *mapping = NULL; // large memory mapping

// ----------------------------------------------
size_t getPhysicalMemorySize() {
    struct sysinfo info;
    sysinfo(&info);
    return (size_t) info.totalram * (size_t) info.mem_unit;
}

// ----------------------------------------------
const char *getCPUModel() {
    static char model[64];
    char *buffer = NULL;
    size_t n, idx;
    FILE *f = fopen("/proc/cpuinfo", "r");
    while (getline(&buffer, &n, f) > 0) {
        idx = 0;
        if (strncmp(buffer, "Model", 5) == 0 || 
            strncmp(buffer, "model name", 10) == 0) 
	    {
            while (buffer[idx] != ':')
                idx++;
            idx += 2;
            strcpy(model, &buffer[idx]);
            idx = 0;
            while (model[idx] != '\n')
                idx++;
            model[idx] = 0;
            break;
        }
    }
    fclose(f);
    return model;
}

// ----------------------------------------------

void setupMapping() {

    // try 1GB huge page
    mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE |
                    (30 << MAP_HUGE_SHIFT), -1, 0);
    if ((void *)mapping == MAP_FAILED) {
        // try 2MB huge page
        mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE,
                        -1, 0);
        if ((void *)mapping == MAP_FAILED) {
            // nomal page allocation
            mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
            if ((void *)mapping == MAP_FAILED) {
                perror("alloc failed");
                exit(1);
            } else
                logInfo("small page mapping (%zu KB)\n", g_page_size / 1024);
        } else
            logInfo("%s huge page mapping\n", "2MB");
    } else
        logInfo("%s huge page mapping\n", "1GB");

    assert(mapping != (void *) -1);

    logDebug("%s", "Initialize large memory block...\n");
    for (size_t index = 0; index < mapping_size; index += g_page_size) {
        pointer *temporary =
            reinterpret_cast<pointer *>(static_cast<uint8_t *>(mapping)
                                        + index);
        temporary[0] = index;
    }
    logDebug("%s", "done!\n");
}

// ------------ CHA perf-counter slice identification (from slicemap.c) ----------------

static int perf_open(int type, uint64_t config, int cpu) {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type        = type;
    attr.config      = config;
    attr.size        = sizeof(attr);
    attr.disabled    = 1;
    attr.inherit     = 1;
    attr.sample_type = PERF_SAMPLE_IDENTIFIER;
    return (int)syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0);
}

// Arm all CHA counters, fire 4096 NT stores, read back counts.
static void cha_probe(const void *addr, int ncha, int base_type,
                      uint64_t config, long long *counts)
{
    int fds[MAX_SLICES];
    void *cl = (void *)((uintptr_t)addr & ~63UL);

    for (int i = 0; i < ncha; i++) {
        fds[i] = perf_open(base_type + i, config, 0);
        if (fds[i] < 0) { counts[i] = 0; continue; }
        ioctl(fds[i], PERF_EVENT_IOC_RESET,  0);
        ioctl(fds[i], PERF_EVENT_IOC_ENABLE, 0);
    }

    REP4K(NT_STORE(cl);)
    asm volatile("mfence" ::: "memory");

    for (int i = 0; i < ncha; i++) {
        if (fds[i] < 0) { counts[i] = 0; continue; }
        ioctl(fds[i], PERF_EVENT_IOC_DISABLE, 0);
        long long v = 0;
        if (read(fds[i], &v, sizeof(v)) != sizeof(v)) v = 0;
        counts[i] = v;
        close(fds[i]);
    }

    /* drain TOR to prevent count bleed into next probe */
    asm volatile("mfence\n\t clflush (%0)\n\t mfence\n\t" : : "r"(cl) : "memory");
    *(volatile char *)cl;
    asm volatile("mfence" ::: "memory");
}

// Run 3 probes, return winning CHA index. -1 if unreliable.
static int identify_slice(const void *addr, int ncha, int base_type,
                           uint64_t config)
{
    long long h[MAX_SLICES];
    int votes[3];

    for (int t = 0; t < 3; t++) {
        cha_probe(addr, ncha, base_type, config, h);

        int best = 0;
        for (int i = 1; i < ncha; i++)
            if (h[i] > h[best]) best = i;

        votes[t] = (h[best] >= MIN_SIGNAL) ? best : -1;
    }

    /* require 2-of-3 agreement */
    if (votes[0] == votes[1] && votes[0] >= 0) return votes[0];
    if (votes[0] == votes[2] && votes[0] >= 0) return votes[0];
    if (votes[1] == votes[2] && votes[1] >= 0) return votes[1];
    return -1;
}

// ----------------------------------------------
long utime() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec) * 1000000 + (tv.tv_usec);
}


// ----------------------------------------------

uint64_t rdtsc() {
#if defined(__aarch64__)
    uint64_t virtual_timer_value;
    asm volatile("isb");
    asm volatile("mrs %0, cntvct_el0" : "=r" (virtual_timer_value));
    return virtual_timer_value;
#else
    uint64_t a, d;
    asm volatile ("xor %%rax, %%rax\n" "cpuid"::: "rax", "rbx", "rcx", "rdx");
    asm volatile ("rdtscp" : "=a" (a), "=d" (d) : : "rcx");
    a = (d << 32) | a;
    return a;
#endif
}

// ----------------------------------------------
uint64_t rdtsc2() {
#if defined(__aarch64__)
    return rdtsc();
#else
    uint64_t a, d;
    asm volatile ("rdtscp" : "=a" (a), "=d" (d) : : "rcx");
    asm volatile ("cpuid"::: "rax", "rbx", "rcx", "rdx");
    a = (d << 32) | a;
    return a;
#endif
}


static inline void clflush(volatile void *p) {
#if defined(__aarch64__)
    asm volatile("DC CIVAC, %[ad]" : : [ad] "r" (p) : "memory");
#else
    asm volatile("clflush (%0)" : : "r" (p) : "memory");
#endif
}

static inline void clflushopt(volatile void *p) {
#if defined(__aarch64__)
    asm volatile("DC CIVAC, %[ad]" : : [ad] "r" (p) : "memory");
#else
    asm volatile("clflushopt (%0)" : : "r" (p) : "memory");
#endif
}

static inline void clwb(volatile void *p) {
#if defined(__aarch64__)
    asm volatile("DC CVAC, %[ad]" : : [ad] "r" (p) : "memory");
#else
    asm volatile("clwb (%0)" : : "r" (p) : "memory");
#endif
}

static inline void sfence() {
#if defined(__aarch64__)
    asm volatile("DSB SY");
#else
    asm volatile("sfence" ::: "memory");
#endif
}

// Non-temporal store (bypasses cache)
static inline void movnt_store(volatile void *p, uint64_t value) {
#if defined(__aarch64__)
    // ARM64: no native support, use DC instruction to bypass cache
    asm volatile("STR %[val], [%[ad]]\n\t"
                 "DC CVAC, %[ad]"
                 : : [ad] "r" (p), [val] "r" (value) : "memory");
#else
    // x86-64: use movnti for non-temporal store
    asm volatile("movnti %[val], (%[ad])"
                 : : [ad] "r" (p), [val] "r" (value) : "memory");
#endif
}

// Non-temporal load (bypasses cache) - x86 only
static inline uint64_t movnt_load(volatile void *p) {
#if defined(__aarch64__)
    // ARM64: no native support, use DC instruction to bypass cache
    uint64_t val;
    asm volatile("LDR %[val], [%[ad]]\n\t"
                 "DC CIVAC, %[ad]"
                 : [val] "=r" (val) : [ad] "r" (p) : "memory");
    return val;
#else
    // prefetchnta + cached load + clflushopt to simulate non-temporal load
    uint64_t val;
    asm volatile("prefetchnta (%0)" : : "r" (p) : "memory");
    val =  *(volatile uint64_t *)p;
    clflushopt(p);
    return val;
#endif
}

char *getAccessModeString(int mode) {
    if (g_cache_mode == 0) {
        switch (mode) {
        case 0:
            return (char *)"read";
        case 1:
            return (char *)"write";
        }
    } else if (g_cache_mode == 1) {
        switch (mode) {
        case 0:
            return (char *)"read+clflushopt";
        case 1:
            return (char *)"write+clwb";
        }
    } else if (g_cache_mode == 2) {
        switch (mode) {
        case 0:
            return (char *)"read+clflush";
        case 1:
            return (char *)"write+clflush";
        }
    } else if (g_cache_mode == 3) {
        switch (mode) {
        case 0:
            return (char *)"non-temporal read";
        case 1:
            return (char *)"non-temporal write";
        }
    }
    return (char *)"unknown";
}

// Worker thread argument
struct ThreadArg {
    int id;
    long *counter;
    std::vector<pointer> *local_set;
};

// Each thread repeatedly accesses all addresses in sets[0] until g_quit_signal
// is set. It increments its own counter for each full traversal of the set.
static void *access_all_thread(void *arg) {
    ThreadArg *a = (ThreadArg *)arg;
    long *ctr = a->counter;
    int cpu_id = a->id; // bind thread to core with same id as thread id

    logInfo("Setting CPU affinity to core %d\n", cpu_id);
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu_id, &set);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &set) != 0) {
        perror("sched_setaffinity");
        exit(1);
    }

    // create a local copy of sets[0] to avoid pointer chasing and improve locality
    std::vector<pointer> *local_set = a->local_set;

    logInfo("Thread %d: accessing %ld addresses in a loop...\n", cpu_id, (long)local_set->size());

    // prepare raw pointer + size for tight loops (avoids repeated bounds checks)
    pointer *data = local_set->empty() ? nullptr : local_set->data();
    size_t n = local_set->size();

    time_t t0 = utime();
    long dur_in_us = 0;
    // main loop
    int cur_access = g_access_type;
    while (!g_quit_signal) {
        if (cur_access != g_access_type) {
            dur_in_us = utime() - t0;
            long long t_bytes = (long long)local_set->size() * *ctr * 64LL;
            double mbps = (double)t_bytes / (double)dur_in_us * 1000000.0 / (1024.0*1024.0);
            printf("Thread %d: iters: %ld  Bandwidth: %.1f MB/s\n", cpu_id, *ctr, mbps);

            cur_access = g_access_type;
            logInfo("Thread %d: switching access type to %s\n",
                    cpu_id, (cur_access == 1) ? "write" : "read");
            t0 = utime();
            *ctr = 0; // reset counter
        }
        if (cur_access == 0) {
            // read attack
            for (size_t j = 0; j < n; ++j) {
                if (g_cache_mode == 0) {
                    // normal cached read
                    *((volatile int *)data[j]);
                } else if (g_cache_mode == 1) {
                    // read from the address and flush it
                    *((volatile int *)data[j]);
                    clflushopt((void *)data[j]);
                } else if (g_cache_mode == 2) {
                    // read from the address and flush it
                    *((volatile int *)data[j]);
                    clflush((void *)data[j]);
                } else if (g_cache_mode == 3) {
                    // non-temporal read
                    movnt_load((void *)data[j]);
                }
            }
        } else if (cur_access == 1) {
            // write attack
            for (size_t j = 0; j < n; ++j) {
                if (g_cache_mode == 0) {
                    // normal cached write
                    *((volatile int *)data[j]) = 0xdeadbeef;
                } else if (g_cache_mode == 1) {
                    // write to the address and clean it
                    *((volatile int *)data[j]) = 0xdeadbeef;
                    clwb((void *)data[j]); // if clwb is not supported, use clflushopt or clflush instead
                } else if (g_cache_mode == 2) {
                    // write to the address and flush it
                    *((volatile int *)data[j]) = 0xdeadbeef;
                    clflush((void *)data[j]);
                } else if (g_cache_mode == 3) {
                    // non-temporal write
                    movnt_store((void *)data[j], 0xdeadbeef);
                }
            }
        }
        (*ctr)++;
    }
    dur_in_us = utime() - t0;
    long long t_bytes = (long long)local_set->size() * (*ctr) * 64LL;
    double mbps = (double)t_bytes / (double)dur_in_us * 1000000.0 / (1024.0*1024.0);
    printf("Thread %d: iters: %ld  Bandwidth: %.1f MB/s\n", cpu_id, *ctr, mbps);

    return NULL;
}

// ----------------------------------------------
int main(int argc, char *argv[]) {
    int cpu_affinity = 0;
    int num_threads = 1;

    // Long options for slice parameters
    static struct option long_options[] = {
        {"base",         required_argument, 0, 'B'},
        {"event",        required_argument, 0, 'E'},
        {"slices",       required_argument, 0, 'S'},
        {"target-slice", required_argument, 0, 'T'},
        {0, 0, 0, 0}
    };

    int c;
    // parse command line arguments
    while ((c = getopt_long(argc, argv, "a:c:g:m:k:v:f:n:", long_options, NULL)) != EOF) {
        switch (c) {
        case 'a':
            g_access_type = (strncmp(optarg, "write", 5) == 0) ? 1 : 0;
            break;
        case 'c':
            cpu_affinity = atoi(optarg);
            break;
        case 'g':
            mapping_size = atol(optarg) * 1024ULL * 1024 * 1024;
            break;
        case 'm':
            mapping_size = atol(optarg) * 1024ULL * 1024;
            break;
        case 'k':
            g_target_n = atoi(optarg);
            break;
        case 'v':
            verbosity = atoi(optarg);
            break;
        case 'f':
            g_cache_mode = atoi(optarg);
            break;
        case 'n':
            num_threads = atoi(optarg);
            if (num_threads <= 0) num_threads = 1;
            break;
        case 'B':
            g_base_type = (int)strtoul(optarg, NULL, 16);
            break;
        case 'E':
            g_event_cfg = strtoul(optarg, NULL, 16);
            break;
        case 'S':
            g_nslices = atoi(optarg);
            break;
        case 'T':
            g_target_slice = atoi(optarg);
            break;
        default:
            printf("Usage: %s [options]\n"
                   "Required:\n"
                   "  --base    <hex>        perf base type for uncore_cha_0\n"
                   "  --event   <hex>        perf event config (e.g. 0xf50)\n"
                   "  --slices  <N>          number of LLC slices (CHAs)\n"
                   "Optional:\n"
                   "  --target-slice <N>     which slice to attack (default: 0)\n"
                   "  -m <MB>                memory size in MB (default: 1024)\n"
                   "  -g <GB>                memory size in GB\n"
                   "  -k <N>                 target addresses to collect (default: 500)\n"
                   "  -c <cpu>               CPU affinity (default: 0)\n"
                   "  -a <read|write>        access type (default: read)\n"
                   "  -f <0-3>               cache mode (default: 1)\n"
                   "  -n <threads>           number of attack threads (default: 1)\n"
                   "  -v <level>             verbosity (default: 1)\n",
                   argv[0]);
            exit(0);
        }
    }

    // Validate required parameters
    if (g_base_type < 0 || g_event_cfg == 0 || g_nslices <= 0) {
        fprintf(stderr, "Error: --base, --event, and --slices are all required.\n");
        exit(1);
    }
    if (g_target_slice < 0 || g_target_slice >= g_nslices) {
        fprintf(stderr, "Error: --target-slice must be in [0, %d)\n", g_nslices);
        exit(1);
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Error: must run as root (perf_event_open for uncore events)\n");
        exit(1);
    }

    logInfo("Setting CPU affinity to core %d\n", cpu_affinity);
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_affinity, &cpuset);
    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
        perror("sched_setaffinity");
        exit(1);
    }

    srand(time(NULL));
    g_page_size = sysconf(_SC_PAGESIZE);
    setupMapping();

    printf("=== oneslice_attacker ===\n");
    printf("Slices       : %d\n", g_nslices);
    printf("Target slice : %d\n", g_target_slice);
    printf("Base type    : 0x%x\n", g_base_type);
    printf("Event cfg    : 0x%lx\n", (unsigned long)g_event_cfg);
    printf("Target addrs : %d\n", g_target_n);
    printf("Mem size     : %zu MB\n", mapping_size / (1024 * 1024));
    printf("Access mode  : %s\n", getAccessModeString(g_access_type));
    printf("Threads      : %d\n", num_threads);
    printf("CPU affinity : %d\n", cpu_affinity);
    printf("\n");

    // ---- Slice discovery using CHA perf counters ----
    printf("Discovering addresses in slice %d...\n", g_target_slice);

    std::vector<pointer> slice_addrs;
    long long total_probes = 0;
    long long accepted_probes = 0;

    while ((int)slice_addrs.size() < g_target_n) {
        // pick a random cache-line-aligned address from the mapping
        size_t offset = ((size_t)rand() % (mapping_size / 64)) * 64;
        void *cl = (void *)((uintptr_t)((char *)mapping + offset) & ~63UL);

        // touch to ensure mapping is live
        *(volatile char *)cl = 0;

        total_probes++;

        int slice = identify_slice(cl, g_nslices, g_base_type, g_event_cfg);

        if (slice >= 0) {
            accepted_probes++;

            if (slice == g_target_slice) {
                slice_addrs.push_back((pointer)cl);

                if (slice_addrs.size() % 50 == 0 || (int)slice_addrs.size() == g_target_n) {
                    printf("\r  Collected %zu / %d addresses (probes: %lld, accept: %.1f%%)",
                           slice_addrs.size(), g_target_n, total_probes,
                           total_probes > 0 ? 100.0 * accepted_probes / total_probes : 0.0);
                    fflush(stdout);
                }
            }
        }
    }
    printf("\n\nSlice discovery complete.\n");
    printf("  Total probes  : %lld\n", total_probes);
    printf("  Accepted      : %lld (%.1f%%)\n", accepted_probes,
           total_probes > 0 ? 100.0 * accepted_probes / total_probes : 0.0);
    printf("  Addresses     : %zu in slice %d\n\n", slice_addrs.size(), g_target_slice);

    // Store found addresses as a single set
    sets.push_back(slice_addrs);

    // access all addresses in the sets[0] using multiple threads
    if (sets.empty()) {
        logWarning("%s\n", "No sets found, nothing to access");
        exit(1);
    }

    int64_t total_addresses = 0;
    size_t min_set_size = SIZE_MAX;
    for (const auto& set : sets) {
        total_addresses += set.size();
        if (set.size() < min_set_size) {
            min_set_size = set.size();
        }
    }
    logInfo("Total %ld addresses found in %zu sets.\n", total_addresses, sets.size());
    printf("Accessing (%s) addresses in %ld sets (%ld addresses) with %d threads...\n",
            getAccessModeString(g_access_type),
            sets.size(), min_set_size * sets.size(), num_threads);

    std::vector<pthread_t> threads(num_threads);
    std::vector<ThreadArg> args(num_threads);
    std::vector<long> counters(num_threads, 0);
    std::vector<std::vector<pointer>> local_sets(num_threads);

    // divide addresses in sets into num_threads local sets
    for (int i = 0; i < num_threads; ++i) {
        local_sets[i].clear();
    }

    // distribute found addresses evenly to each thread's local set
    for (size_t j = 0; j < min_set_size; ++j) {
        // distribute addresses from each set to the local sets
        for(int i = 0; i < sets.size(); ++i ) {
            if (j == 0) logDebug("sets[%d][%zu] = 0x%lx\n", i, j, sets[i][j]);
            local_sets[j % num_threads].push_back(sets[i][j]);
        }
    }

    long t0 = utime();

    for (int i = 0; i < num_threads; ++i) {
        args[i].id = cpu_affinity + i;
        args[i].counter = &counters[i];
        args[i].local_set = &local_sets[i];

        int rc = pthread_create(&threads[i], NULL, access_all_thread, &args[i]);
        if (rc != 0) {
            perror("pthread_create");
            // continue creating remaining threads or exit? we'll exit
            g_quit_signal = 1;
            break;
        }
    }

    // if SIGINT is received, set g_quit_signal to 1
    signal(SIGINT, [](int signum) {
        g_quit_signal = 1;
    });

    // if SIGUSR1 is received, set g_access_type to 0 (read)
    signal(SIGUSR1, [](int signum) {
        g_access_type = 0;
    });

    // if SIGUSR2 is received, set g_access_type to 1 (write)
    signal(SIGUSR2, [](int signum) {
        g_access_type = 1;
    });

    // main thread just waits for SIGINT to set g_quit_signal
    int cur_access = g_access_type;
    while (!g_quit_signal) {
        if (cur_access != g_access_type) {
            cur_access = g_access_type;
            printf("Main thread: switching access type to %s\n",
                    (cur_access == 1) ? "write" : "read");
            t0 = utime();
        }
        sleep(1);
    }

    // join threads and aggregate counters
    for (int i = 0; i < num_threads; ++i) {
        pthread_join(threads[i], NULL);
    }

    long dur_in_us = utime() - t0;
    long long accessed_bytes = 0;
    // per-thread b/w
    for (int i = 0; i < num_threads; ++i) {
        long long t_bytes = (long long)local_sets[i].size() * counters[i] * 64LL;
        // double mbps = (double)t_bytes / (double)dur_in_us * 1000000.0 / (1024.0*1024.0);
        // printf("Thread %d: iters: %ld  Bandwidth: %.1f MB/s\n", i, counters[i], mbps);
        accessed_bytes += t_bytes;
    }
    // total b/w
    double total_mbps = (double)accessed_bytes / (double)dur_in_us * 1000000.0 / (1024.0*1024.0);
    printf("Total aggregate bandwidth: %.1f MB/s\n", total_mbps);
    return 0;
}
