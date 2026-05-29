#ifndef BLINK_EPOLL_SHIM_H_
#define BLINK_EPOLL_SHIM_H_
#ifdef __EMSCRIPTEN__
// Minimal epoll() implemented over poll(), for the emscripten/wasm build whose
// musl sysroot ships no <sys/epoll.h> / epoll_* functions. Enough for an X
// server (Xvfb) event loop: level-triggered readiness over a tracked fd set.
#include <stdint.h>

#define EPOLL_CLOEXEC 02000000

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

// Event bits — match Linux values (also what blink's *_LINUX constants use).
#define EPOLLIN      0x001
#define EPOLLPRI     0x002
#define EPOLLOUT     0x004
#define EPOLLERR     0x008
#define EPOLLHUP     0x010
#define EPOLLRDHUP   0x2000
#define EPOLLET      0x80000000u
#define EPOLLONESHOT 0x40000000u

typedef union epoll_data {
  void *ptr;
  int fd;
  uint32_t u32;
  uint64_t u64;
} epoll_data_t;

struct epoll_event {
  uint32_t events;
  epoll_data_t data;
} __attribute__((packed));

int epoll_create1(int flags);
int epoll_create(int size);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev);
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
// blink calls epoll_pwait/epoll_pwait2; route them through epoll_wait (the
// signal mask is applied by blink around the call, so the mask arg is ignored
// here). Declared to match the call sites.
struct timespec;
int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout,
                const void *sigmask);
int epoll_pwait2(int epfd, struct epoll_event *events, int maxevents,
                 const struct timespec *timeout, const void *sigmask);

#endif /* __EMSCRIPTEN__ */
#endif /* BLINK_EPOLL_SHIM_H_ */
