#ifdef __EMSCRIPTEN__
// poll()-backed epoll() for the wasm build (no <sys/epoll.h> in the emscripten
// sysroot). Level-triggered; enough for an X server event loop.
#include "blink/epoll_shim.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define EPOLL_MAX_INSTANCES 64
#define EPOLL_MAX_WATCHES 1024

struct EpollWatch {
  int fd;            // -1 = empty slot
  uint32_t events;   // requested EPOLL* bits
  epoll_data_t data; // opaque user data echoed back
};

struct EpollInstance {
  int handle;        // the real (pipe) fd handed to the guest; -1 = free
  struct EpollWatch w[EPOLL_MAX_WATCHES];
};

static struct EpollInstance g_epoll[EPOLL_MAX_INSTANCES];

static struct EpollInstance *FindByHandle(int handle) {
  for (int i = 0; i < EPOLL_MAX_INSTANCES; i++)
    if (g_epoll[i].handle == handle) return &g_epoll[i];
  return 0;
}

int epoll_create1(int flags) {
  int slot = -1;
  for (int i = 0; i < EPOLL_MAX_INSTANCES; i++)
    if (g_epoll[i].handle == 0) { slot = i; break; }
  if (slot < 0) { errno = EMFILE; return -1; }
  // Back the epoll fd with the read end of a pipe so it's a real, closable fd
  // distinct from any watched fd. The write end is parked (never written).
  int pp[2];
  if (pipe(pp) != 0) return -1;
  close(pp[1]);
  int h = pp[0];
  if (flags & EPOLL_CLOEXEC) fcntl(h, F_SETFD, FD_CLOEXEC);
  if (h == 0) {  // never use 0 as a sentinel handle
    int h2 = dup(h);
    close(h);
    h = h2;
  }
  struct EpollInstance *e = &g_epoll[slot];
  e->handle = h;
  for (int j = 0; j < EPOLL_MAX_WATCHES; j++) e->w[j].fd = -1;
  return h;
}

int epoll_create(int size) {
  (void)size;
  return epoll_create1(0);
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev) {
  struct EpollInstance *e = FindByHandle(epfd);
  if (!e) { errno = EBADF; return -1; }
  if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) {
    if (!ev) { errno = EFAULT; return -1; }
    int found = -1, free_slot = -1;
    for (int j = 0; j < EPOLL_MAX_WATCHES; j++) {
      if (e->w[j].fd == fd) { found = j; break; }
      if (e->w[j].fd == -1 && free_slot < 0) free_slot = j;
    }
    if (op == EPOLL_CTL_ADD) {
      if (found >= 0) { errno = EEXIST; return -1; }
      if (free_slot < 0) { errno = ENOSPC; return -1; }
      e->w[free_slot].fd = fd;
      e->w[free_slot].events = ev->events;
      e->w[free_slot].data = ev->data;
    } else {  // MOD
      if (found < 0) { errno = ENOENT; return -1; }
      e->w[found].events = ev->events;
      e->w[found].data = ev->data;
    }
    return 0;
  } else if (op == EPOLL_CTL_DEL) {
    for (int j = 0; j < EPOLL_MAX_WATCHES; j++)
      if (e->w[j].fd == fd) { e->w[j].fd = -1; return 0; }
    errno = ENOENT;
    return -1;
  }
  errno = EINVAL;
  return -1;
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents,
               int timeout) {
  struct EpollInstance *e = FindByHandle(epfd);
  if (!e || maxevents <= 0) { errno = !e ? EBADF : EINVAL; return -1; }
  struct pollfd pfds[EPOLL_MAX_WATCHES];
  int idx[EPOLL_MAX_WATCHES];
  int n = 0;
  for (int j = 0; j < EPOLL_MAX_WATCHES && n < EPOLL_MAX_WATCHES; j++) {
    if (e->w[j].fd < 0) continue;
    short pe = 0;
    if (e->w[j].events & EPOLLIN) pe |= POLLIN;
    if (e->w[j].events & EPOLLOUT) pe |= POLLOUT;
    if (e->w[j].events & EPOLLPRI) pe |= POLLPRI;
    if (e->w[j].events & EPOLLRDHUP) pe |= POLLRDHUP;
    pfds[n].fd = e->w[j].fd;
    pfds[n].events = pe;
    pfds[n].revents = 0;
    idx[n] = j;
    n++;
  }
  // COOPERATIVE SCHEDULING: a blocking poll() freezes the whole wasm thread, so
  // concurrent VMs (X server + client) cannot interleave through it. Force a
  // non-blocking peek (timeout 0): no events -> return 0 (as a timeout) so the
  // guest loops + preempts, letting the scheduler run the other VM; the next
  // slice polls again. Converts blocking waits into cooperative spins.
  (void)timeout;
  int rc = poll(pfds, n, 0);
  if (rc <= 0) return rc;  // 0 = nothing ready now, -1 = error
  int out = 0;
  for (int k = 0; k < n && out < maxevents; k++) {
    if (!pfds[k].revents) continue;
    uint32_t ev = 0;
    if (pfds[k].revents & POLLIN) ev |= EPOLLIN;
    if (pfds[k].revents & POLLOUT) ev |= EPOLLOUT;
    if (pfds[k].revents & POLLPRI) ev |= EPOLLPRI;
    if (pfds[k].revents & POLLERR) ev |= EPOLLERR;
    if (pfds[k].revents & POLLHUP) ev |= EPOLLHUP;
    if (pfds[k].revents & POLLRDHUP) ev |= EPOLLRDHUP;
    events[out].events = ev & (e->w[idx[k]].events | EPOLLERR | EPOLLHUP);
    events[out].data = e->w[idx[k]].data;
    out++;
  }
  return out;
}

int epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
                int timeout, const void *sigmask) {
  (void)sigmask;  // blink applies the guest sigmask around the call
  return epoll_wait(epfd, events, maxevents, timeout);
}

int epoll_pwait2(int epfd, struct epoll_event *events, int maxevents,
                 const struct timespec *timeout, const void *sigmask) {
  (void)sigmask;
  int ms = -1;
  if (timeout) {
    // struct timespec is opaque here; reinterpret as { long sec; long nsec; }.
    const long *ts = (const long *)timeout;
    ms = (int)(ts[0] * 1000 + ts[1] / 1000000);
  }
  return epoll_wait(epfd, events, maxevents, ms);
}
#endif /* __EMSCRIPTEN__ */
