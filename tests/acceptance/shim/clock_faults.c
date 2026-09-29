/*
 * The acceptance harness's interposition layer: fault injection for the
 * clocks and the write boundary.
 *
 * The harness compiles this file at run time and injects it into the process
 * under test with LD_PRELOAD (Linux) or DYLD_INSERT_LIBRARIES (macOS); the
 * release binary's bytes carry none of this and no product input selects it.
 * Orders come from three control files the harness owns:
 *
 *   JAYNSHARE_SHIM_CLOCK  8 little-endian bytes: nanoseconds added to every
 *                         clock the process reads, wall and monotonic alike,
 *                         so no two subsystems disagree. Mapped once
 *                         and read on every clock call, so the harness can
 *                         move a running instance's clock.
 *   JAYNSHARE_SHIM_RENAME file whose bytes are a destination-path suffix:
 *                         non-empty kills the process at the next rename
 *                         whose destination ends with it — the crash between
 *                         the temporary write and the rename.
 *   JAYNSHARE_SHIM_FSIZE  file whose bytes are a byte count set as
 *                         RLIMIT_FSIZE at load: appends past it fail — the
 *                         filled destination.
 *
 * The two platforms replace a function differently. LD_PRELOAD wants the
 * replacement to carry the replaced function's own name and finds the real
 * one behind it with RTLD_NEXT. dyld replaces nothing by name: it reads the
 * __interpose table at the foot of this file, which pairs two *different*
 * symbols, and it leaves this image alone — so here a call by name is the
 * real function, and dlsym(RTLD_NEXT) would hand back the replacement and
 * recurse until the stack ends.
 */

#define _GNU_SOURCE 1

#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach/mach_time.h>

#define SHIM(name) shim_##name
#define REAL(name) name
#define RESOLVE(name) ((void)0)
#define DYLD_INTERPOSE(replacement, replacee)                                 \
    __attribute__((used)) static struct {                                     \
        const void *from;                                                     \
        const void *to;                                                       \
    } interpose_##replacee __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)&replacement, (const void *)&replacee}
#else

#define SHIM(name) name
#define REAL(name) real_##name
#define RESOLVE(name)                                       \
    do {                                                    \
        if (real_##name == NULL) {                          \
            real_##name = dlsym(RTLD_NEXT, #name);          \
        }                                                   \
    } while (0)

static int (*real_clock_gettime)(clockid_t, struct timespec *);
static int (*real_gettimeofday)(struct timeval *, void *);
static time_t (*real_time)(time_t *);
static int (*real_rename)(const char *, const char *);

#endif

static const volatile int64_t *clock_offset_ns;

static const char *control_file(const char *name) {
    const char *value = getenv(name);
    return (value != NULL && value[0] != '\0') ? value : NULL;
}

/* The bytes of a control file, or NULL; short enough to read in one call. */
static const char *file_bytes(const char *path) {
    static char bytes[256];
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return NULL;
    }
    ssize_t n = read(fd, bytes, sizeof bytes - 1);
    close(fd);
    if (n <= 0) {
        return NULL;
    }
    bytes[n] = '\0';
    return bytes;
}

static void apply_offset(struct timespec *t) {
    int64_t ns = (int64_t)t->tv_sec * 1000000000 + (int64_t)t->tv_nsec;
    ns += *clock_offset_ns;
    if (ns < 0) {
        ns = 0;
    }
    t->tv_sec = (time_t)(ns / 1000000000);
    t->tv_nsec = (long)(ns % 1000000000);
}

/* Every clock the product reads moves together, so no two
 * subsystems disagree. Besides the wall and the obvious monotonic clocks,
 * that is the raw and no-sleep variants — std's Instant on macOS reads
 * CLOCK_UPTIME_RAW, and tokio's timers ride std's Instant. */
static int moved_clock(clockid_t clock) {
    switch (clock) {
    case CLOCK_REALTIME:
    case CLOCK_MONOTONIC:
    case CLOCK_MONOTONIC_RAW:
#ifdef CLOCK_UPTIME_RAW
    case CLOCK_UPTIME_RAW:
#endif
#ifdef CLOCK_UPTIME
    case CLOCK_UPTIME:
#endif
#ifdef CLOCK_BOOTTIME
    case CLOCK_BOOTTIME:
#endif
        return 1;
    default:
        return 0;
    }
}

int SHIM(clock_gettime)(clockid_t clock, struct timespec *tp) {
    RESOLVE(clock_gettime);
    int result = REAL(clock_gettime)(clock, tp);
    if (result == 0 && tp != NULL && clock_offset_ns != NULL && moved_clock(clock)) {
        apply_offset(tp);
    }
    return result;
}

int SHIM(gettimeofday)(struct timeval *tv, void *zone) {
    RESOLVE(gettimeofday);
    int result = REAL(gettimeofday)(tv, zone);
    if (result == 0 && tv != NULL && clock_offset_ns != NULL) {
        int64_t us = (int64_t)tv->tv_sec * 1000000 + (int64_t)tv->tv_usec;
        us += *clock_offset_ns / 1000;
        if (us < 0) {
            us = 0;
        }
        tv->tv_sec = (time_t)(us / 1000000);
        tv->tv_usec = (suseconds_t)(us % 1000000);
    }
    return result;
}

time_t SHIM(time)(time_t *out) {
    RESOLVE(time);
    time_t now = REAL(time)(NULL);
    if (clock_offset_ns != NULL) {
        now += (time_t)(*clock_offset_ns / 1000000000);
    }
    if (out != NULL) {
        *out = now;
    }
    return now;
}

int SHIM(rename)(const char *from, const char *to) {
    RESOLVE(rename);
    const char *orders = control_file("JAYNSHARE_SHIM_RENAME");
    if (orders != NULL && to != NULL) {
        const char *bytes = file_bytes(orders);
        if (bytes != NULL) {
            size_t suffix = strlen(bytes);
            size_t length = strlen(to);
            if (length >= suffix && memcmp(to + length - suffix, bytes, suffix) == 0) {
                /* Dead between the temporary write and the rename. */
                _exit(86);
            }
        }
    }
    return REAL(rename)(from, to);
}

#ifdef __APPLE__

static mach_timebase_info_data_t mach_base;

/* The offset in nanoseconds, in the mach clock's own ticks. */
static uint64_t mach_offset_ticks(void) {
    if (clock_offset_ns == NULL) {
        return 0;
    }
    if (mach_base.denom == 0) {
        mach_timebase_info(&mach_base);
    }
    int64_t ns = *clock_offset_ns;
    if (ns < 0) {
        ns = 0;
    }
    return (uint64_t)((ns / 1000) * (int64_t)mach_base.denom / (int64_t)mach_base.numer);
}

uint64_t shim_mach_absolute_time(void) {
    uint64_t ticks = mach_absolute_time();
    if (clock_offset_ns != NULL) {
        ticks += mach_offset_ticks();
    }
    return ticks;
}

uint64_t shim_mach_continuous_time(void) {
    uint64_t ticks = mach_continuous_time();
    if (clock_offset_ns != NULL) {
        ticks += mach_offset_ticks();
    }
    return ticks;
}

DYLD_INTERPOSE(shim_clock_gettime, clock_gettime);
DYLD_INTERPOSE(shim_gettimeofday, gettimeofday);
DYLD_INTERPOSE(shim_time, time);
DYLD_INTERPOSE(shim_mach_absolute_time, mach_absolute_time);
DYLD_INTERPOSE(shim_mach_continuous_time, mach_continuous_time);
DYLD_INTERPOSE(shim_rename, rename);

#endif

/* The once-per-process orders: the clock mapping and the size limit. */
__attribute__((constructor)) static void faults_init(void) {
    const char *clock = control_file("JAYNSHARE_SHIM_CLOCK");
    if (clock != NULL) {
        int fd = open(clock, O_RDONLY);
        if (fd >= 0) {
            void *mapping = mmap(NULL, 8, PROT_READ, MAP_SHARED, fd, 0);
            close(fd);
            if (mapping != MAP_FAILED) {
                clock_offset_ns = (const volatile int64_t *)mapping;
            }
        }
    }
    const char *fsize = control_file("JAYNSHARE_SHIM_FSIZE");
    if (fsize != NULL) {
        const char *bytes = file_bytes(fsize);
        if (bytes != NULL) {
            long long limit = strtoll(bytes, NULL, 10);
            if (limit > 0) {
                struct rlimit capped;
                capped.rlim_cur = (rlim_t)limit;
                capped.rlim_max = (rlim_t)limit;
                setrlimit(RLIMIT_FSIZE, &capped);
            }
        }
    }
}
