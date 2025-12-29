#include <fcntl.h>
#include <sys/mman.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <dirent.h>
#include <limits.h>
#include <memory.h>
#include <stdlib.h>
#include <string.h>

#include <asm/unistd.h>
#include <cpuid.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <sys/syscall.h>
#include <unistd.h>

int event_open(enum perf_type_id type, __u64 config, __u64 exclude_kernel,
               __u64 exclude_hv, __u64 exclude_callchain_kernel, int cpu) {
  static struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = type;
  attr.config = config;
  attr.size = sizeof(attr);
  attr.exclude_kernel = exclude_kernel;
  attr.exclude_hv = exclude_hv;
  attr.exclude_callchain_kernel = exclude_callchain_kernel;
  attr.sample_type = PERF_SAMPLE_IDENTIFIER;
  attr.inherit = 1;
  attr.disabled = 1;

  int fd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, 0);
  if (fd < 0) {
    printf("perf_event_open failed: you forgot sudo or you have no perf event "
           "interface available for the userspace.");
  };

  return fd;
}

int g_pagemap_fd;
size_t g_page_size = 4096;

typedef uint64_t pointer;
pointer frameNumberFromPagemap(pointer pagemapValue) {
    // Bits 0-54 are the page frame number (PFN) if the page is present
    return pagemapValue & ((1ULL << 55) - 1);
}
pointer get_physical_address(pointer virtual_addr) {
    pointer value;
    off_t offset = (virtual_addr / g_page_size) * sizeof(value);
    int got = pread(g_pagemap_fd, &value, sizeof(value), offset);
    assert(got == 8);

    // Check the "page present" flag.
    assert(value & (1ULL << 63));

    pointer frame_num = frameNumberFromPagemap(value);
    return (frame_num * g_page_size) | (virtual_addr & (g_page_size - 1));
}

// ----------------------------------------------
void initPagemap() {
    g_pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
    assert(g_pagemap_fd >= 0);
}


int find_index_of_nth_largest_size_t(size_t *list, size_t nmemb, size_t skip) {
  size_t sorted[nmemb];
  size_t idx[nmemb];
  size_t i, j;
  size_t tmp;
  memset(sorted, 0, sizeof(sorted));
  for (i = 0; i < nmemb; i++) {
    sorted[i] = list[i];
    idx[i] = i;
  }
  for (i = 0; i < nmemb; i++) {
    int swaps = 0;
    for (j = 0; j < nmemb - 1; j++) {
      if (sorted[j] < sorted[j + 1]) {
        tmp = sorted[j];
        sorted[j] = sorted[j + 1];
        sorted[j + 1] = tmp;
        tmp = idx[j];
        idx[j] = idx[j + 1];
        idx[j + 1] = tmp;
        swaps++;
      }
    }
    if (!swaps)
      break;
  }

  return idx[skip];
}

#define BASE_PATH "/sys/bus/event_source/devices/"
#define CBOX_PREFIX "uncore_cbox_"
#define CHA_PREFIX "uncore_cha_"
#define TYPE_FILE "/type"

int get_slice_info(const char *prefix, char *type_value) {
  DIR *dir;
  struct dirent *entry;
  int slices = -1;
  char path[PATH_MAX];

  dir = opendir(BASE_PATH);
  if (!dir) {
    perror("opendir");
    return -1;
  }

  while ((entry = readdir(dir)) != NULL) {
    // printf("%s | %d == %d | %d\n", entry->d_name, entry->d_type, DT_DIR,
    // strncmp(entry->d_name, prefix, strlen(prefix)));
    if (/*entry->d_type == DT_DIR && */ strncmp(entry->d_name, prefix,
                                                strlen(prefix)) == 0) {
      int X = atoi(entry->d_name + strlen(prefix));
      if (X > slices) {
        slices = X;
      }

      if (X == 0) {
        snprintf(path, sizeof(path), "%s%s%d%s", BASE_PATH, prefix, X,
                 TYPE_FILE);
        FILE *type_file = fopen(path, "r");
        if (type_file) {
          if (fgets(type_value, 10, type_file) != NULL) {
            type_value[strcspn(type_value, "\n")] = '\0';
          }
          fclose(type_file);
        } else {
          perror("fopen");
        }
      }
    }
  }
  closedir(dir);
  return slices + 1;
}

// ---------------------------------------------------------------------------
size_t find_slice_perf(void *address, int repeat, int *slice_count,
                       unsigned long *config, int *base) {
#define REP4(x) x x x x
#define REP16(x) REP4(x) REP4(x) REP4(x) REP4(x)
#define REP256(x)                                                              \
  REP16(x)                                                                     \
  REP16(x)                                                                     \
  REP16(x)                                                                     \
  REP16(x)                                                                     \
  REP16(x)                                                                     \
  REP16(x)                                                                     \
  REP16(x) REP16(x) REP16(x) REP16(x) REP16(x) REP16(x) REP16(x) REP16(x)      \
      REP16(x) REP16(x)
#define REP1K(x) REP256(x) REP256(x) REP256(x) REP256(x)
#define REP4K(x) REP1K(x) REP1K(x) REP1K(x) REP1K(x)

  size_t hist[256];
  memset(hist, 0, sizeof(hist));

  int fds[256];
  size_t ev_hist[256];

  char type_value[10] = {0};
  int slices = get_slice_info(CBOX_PREFIX, type_value);
  // printf("%d\n", slices);

  if (slices > 0) {
    printf("Found %d uncore CBoxes | Perf type: %s\n", slices, type_value);
  } else {
    slices = get_slice_info(CHA_PREFIX, type_value);
    if (slices >= 0) {
      printf("Found %d uncore CBoxes | Perf type: %s\n", slices, type_value);
    } else {
      printf("Neither uncore_cbox_0 nor uncore_cha_0 found.\n");
      return 1;
    }
  }

  int did_find = 0;
  void *start_address = address;
  int mask = 0x7;

  while (!did_find && mask < 0xff) {
    address = start_address;
    mask = (mask << 1) | 0x1;
    memset(ev_hist, 0, sizeof(ev_hist));

    for (int i = 0; i < repeat; i++) {
      // printf("Round %d / %d\n", i + 1, repeat);
      for (int ev = 0; ev < 0xff; ev++) {
        unsigned long config = mask * 256 + ev;
        long long sum = 0;
        int qualify = 0;
        for (int i = 0; i < slices; i++) {
          // printf(":Open %d | %zd\n", atoi(type_value) + i, config);
          fds[i] = event_open(atoi(type_value) + i, config, 0, 0, 0, i);
          if (fds[i] < 0)
            break;
          ioctl(fds[i], PERF_EVENT_IOC_ENABLE, 0);
          ioctl(fds[i], PERF_EVENT_IOC_RESET, 0);

          REP4K(asm volatile("mfence; clflush (%0); mfence; \n" : : "r"(
              address) : "memory");
                *(volatile char *)address;)

          ioctl(fds[i], PERF_EVENT_IOC_DISABLE, 0);

          long long result = 0;
          int ret = read(fds[i], &result, sizeof(result));
          hist[i] = result;
          close(fds[i]);
          // printf("CPU %d: %zd\n", i, result);
          if (result >= 4096 && result < 8000) {
            // printf("Maybe event %x (%zd)\n", ev, result);
            qualify = 1;
          }
          sum += result;
        }
        if (sum >= 4096 && sum < 8000 && qualify) {
          // printf("-> Could be 0x%zx (%lld)\n", config, sum);
          ev_hist[ev]++;
        }
      }
      address = (void *)((size_t)address + 64);
    }
    int potential = find_index_of_nth_largest_size_t(ev_hist, 256, 0);
    // printf("Check [0x%zx]: %zd ?= %d\n", potential + mask * 256,
    // ev_hist[potential], repeat);
    if (ev_hist[potential] == repeat) {
      did_find = 1;
    }
  }

  *config = find_index_of_nth_largest_size_t(ev_hist, 256, 0) + mask * 256;
  *base = atoi(type_value);
  *slice_count = slices;
  return 0;
}

size_t measure_slice_perf(void *address, int slices, unsigned long config,
                          int type) {
#define REP4(x) x x x x
#define REP16(x) REP4(x) REP4(x) REP4(x) REP4(x)
#define REP256(x)                                                              \
  REP16(x)                                                                     \
  REP16(x)                                                                     \
  REP16(x)                                                                     \
  REP16(x)                                                                     \
  REP16(x)                                                                     \
  REP16(x)                                                                     \
  REP16(x) REP16(x) REP16(x) REP16(x) REP16(x) REP16(x) REP16(x) REP16(x)      \
      REP16(x) REP16(x)
#define REP1K(x) REP256(x) REP256(x) REP256(x) REP256(x)
#define REP4K(x) REP1K(x) REP1K(x) REP1K(x) REP1K(x)

  size_t hist[256];
  memset(hist, 0, sizeof(hist));

  int fds[256];
  // printf("%d\n", *(volatile char*)address);

  // printf("\nAddress: 0x%zx\n", address);
  for (int i = 0; i < slices; i++) {
    // printf("Open %d | %zd\n", type + i, config);
    fds[i] = event_open(type + i, config, 0, 0, 0, i);
    if (fds[i] < 0)
      break;
    ioctl(fds[i], PERF_EVENT_IOC_ENABLE, 0);
    ioctl(fds[i], PERF_EVENT_IOC_RESET, 0);

    REP4K(asm volatile(
              "mfence; clflush (%0); mfence; \n" : : "r"(address) : "memory");
          *(volatile char *)address;)
    REP4K(asm volatile(
              "mfence; clflush (%0); mfence; \n" : : "r"(address) : "memory");
          *(volatile char *)address;)

    ioctl(fds[i], PERF_EVENT_IOC_DISABLE, 0);

    long long result = 0;
    int ret = read(fds[i], &result, sizeof(result));
    hist[i] = result;
    // printf("Slice %d: %zd\n", i, result);
    close(fds[i]);
  }

  int idx = find_index_of_nth_largest_size_t(hist, slices, 0);
  if (hist[idx] < 8192) {
    printf("Expected >= 8192, got %zd\n", hist[idx]);
    return -1;
  }
  return idx;
}

int log_2(uint64_t x) {
  int result = 0;
  if (x == 0)
    return 0;
  x -= 1;
  while (x > 0) {
    x >>= 1;
    result++;
  }
  return result;
}

char __attribute__((aligned(4096))) data[4096 * 1024];

void print_usage(const char *prog_name) {
  printf(
      "Usage: %s [--memsize <GB>] [--threshold <int>] [--base <hex> --event <hex> --slices <int>]\n",
      prog_name);
}

int main(int argc, char *argv[]) {
  if (geteuid() != 0) {
    printf("Error: This program must be run as root.\n");
    return 1;
  }

  if (argc < 1 || argc > 11) {
    print_usage(argv[0]);
    return 1;
  }

  int slices = -1, base = 0;
  unsigned long event = 0;
  int base_set = 0, event_set = 0, slices_set = 0;
  uint64_t memsize = 1ULL * 1024 * 1024 * 1024;
  int threshold = 1000;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--memsize") == 0) {
      if (i + 1 < argc) {
        memsize = (uint64_t)atoi(argv[++i]) * 1024 * 1024 * 1024;
      } else {
        print_usage(argv[0]);
        return 1;
      }
    } else if (strcmp(argv[i], "--threshold") == 0) {
      if (i + 1 < argc) {
        threshold = atoi(argv[++i]);
      } else {
        print_usage(argv[0]);
        return 1;
      }
    } else if (strcmp(argv[i], "--base") == 0) {
      if (i + 1 < argc) {
        base = strtoul(argv[++i], NULL, 16);
        base_set = 1;
      } else {
        print_usage(argv[0]);
        return 1;
      }
    } else if (strcmp(argv[i], "--event") == 0) {
      if (i + 1 < argc) {
        event = strtoul(argv[++i], NULL, 16);
        event_set = 1;
      } else {
        print_usage(argv[0]);
        return 1;
      }
    } else if (strcmp(argv[i], "--slices") == 0) {
      if (i + 1 < argc) {
        slices = atoi(argv[++i]);
        slices_set = 1;
      } else {
        print_usage(argv[0]);
        return 1;
      }
    } else {
      print_usage(argv[0]);
      return 1;
    }
  }

  if ((base_set || event_set || slices_set) &&
      !(base_set && event_set && slices_set)) {
    printf("Error: --base, --event, and --slices must be used together.\n");
    return 1;
  }

  printf("Memory size: %lu GB\n", memsize / (1024 * 1024 * 1024));
  printf("Threshold: %d\n", threshold);
  if (base_set && event_set && slices_set) {
    printf("Base: 0x%x\n", base);
    printf("Event: 0x%lx\n", event);
    printf("Slices: %d\n", slices);
  }

  initPagemap();
  /* Measurements. */
  if (!base_set || !event_set || !slices) {
    printf(
        "Looking for performance counter to use, this might take a while...\n");
    int perf = find_slice_perf(data, 3, &slices, &event, &base);
  }

  printf("%d slices, base 0x%x, event 0x%zx\n", slices, base, event);

  char *allocated = mmap(0, memsize, PROT_READ | PROT_WRITE,
                         MAP_ANON | MAP_PRIVATE | MAP_POPULATE, -1, 0);
  if (allocated == MAP_FAILED) {
    perror("mmap");
    return 1;
  }

  uint64_t **slice_addrs = malloc(slices * sizeof(uint64_t*));
  int *slice_counts = calloc(slices, sizeof(int));
  for (int s = 0; s < slices; s++) {
    slice_addrs[s] = malloc(threshold * sizeof(uint64_t));
  }

  srand(time(NULL));

  int last_perc = -1;
  while (1) {
    size_t offset = ((size_t)rand() % (memsize / 64)) * 64;
    void *vaddr = allocated + offset;
    *(volatile char *)vaddr; // fault in the page
    void *paddr = (void *)get_physical_address((pointer)vaddr);
    int slice = (int)measure_slice_perf(vaddr, slices, event, base);
    if (slice == -1) continue; // invalid measurement
    if (slice_counts[slice] < threshold) {
      slice_addrs[slice][slice_counts[slice]++] = (uint64_t)paddr;
    }
    int all_full = 1;
    for (int s = 0; s < slices; s++) {
      if (slice_counts[s] < threshold) {
        all_full = 0;

        int perc = slice_counts[s] * 100 / threshold;
        if (perc != last_perc) {
          last_perc = perc;
          printf("\r%3d%%  ", perc);
          fflush(stdout);
        }
        break;
      }
    }
    if (all_full) break;
  }

  for (int s = 0; s < slices; s++) {
    char filename[20];
    sprintf(filename, "slice%d.txt", s);
    FILE *f = fopen(filename, "w");
    if (f == NULL) {
      printf("Error opening %s\n", filename);
      continue;
    }
    for (int i = 0; i < slice_counts[s]; i++) {
      fprintf(f, "0x%lx\n", slice_addrs[s][i]);
    }
    fclose(f);
  }

  munmap(allocated, memsize);
  for (int s = 0; s < slices; s++) {
    free(slice_addrs[s]);
  }
  free(slice_addrs);
  free(slice_counts);
  printf("Done!\n");
  exit(0);
}
