#ifdef __EMSCRIPTEN__
// poll()-backed epoll() for the wasm build (no <sys/epoll.h> in the emscripten
// sysroot). Level-triggered; enough for an X server event loop.
#include "blink/epoll_shim.h"
#include "blink/unixsock_shim.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
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
    { extern void blink_usmark(const char*); char b[64];
      snprintf(b, sizeof(b), "epoll_ctl %s fd=%d events=0x%x",
               op==EPOLL_CTL_ADD?"ADD":"MOD", fd, ev->events); blink_usmark(b); }
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
    { extern void blink_usmark(const char*); char b[48];
      snprintf(b, sizeof(b), "epoll_ctl DEL fd=%d", fd); blink_usmark(b); }
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
  // In-process unix LISTENER readiness lives in shared memory (npending), not in
  // the emscripten host pipe (whose poll is NOT coherent across worker threads),
  // so a blocking poll on the listener fd would never wake when a peer thread
  // connects. Pre-check listener readiness from shared memory; if a connection is
  // pending, synthesize POLLIN without blocking. Also CAP the poll timeout so we
  // re-check shared listener state periodically rather than block forever on a
  // pipe that won't signal cross-thread.
  for (int k = 0; k < n; k++) {
    if (blink_unix_listener_readable(pfds[k].fd) == 1) pfds[k].revents |= POLLIN;
    // Connected in-process endpoints carry data in shared rings, invisible to
    // the host pipe poll; surface ring readiness here too so the X server wakes
    // to read its clients.
    if (blink_unix_conn_readable(pfds[k].fd) == 1) {
      pfds[k].revents |= POLLIN;
      { extern void blink_usmark(const char*); char b[64];
        snprintf(b, sizeof(b), "epoll conn-ready fd=%d", pfds[k].fd); blink_usmark(b); }
    }
  }
  int presynth = 0;
  for (int k = 0; k < n; k++) if (pfds[k].revents) presynth = 1;
  int rc;
  if (presynth) {
    rc = 0; for (int k = 0; k < n; k++) if (pfds[k].revents) rc++;
  } else {
    int to = timeout; if (to < 0 || to > 20) to = 20;  // cap so we recheck npending
    rc = poll(pfds, n, to);
    for (int k = 0; k < n; k++)
      if (blink_unix_listener_readable(pfds[k].fd) == 1 ||
          blink_unix_conn_readable(pfds[k].fd) == 1) {
        if (!pfds[k].revents) rc++;
        pfds[k].revents |= POLLIN;
      }
  }
  if (rc <= 0) return rc;  // 0 = timeout, -1 = error
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
    if (blink_unix_conn_readable(pfds[k].fd) >= 0) {
      extern void blink_usmark(const char*); char b[96];
      snprintf(b, sizeof(b), "epoll_wait RET fd=%d revents=0x%x out_events=0x%x watch=0x%x",
               pfds[k].fd, (unsigned)pfds[k].revents, events[out].events,
               e->w[idx[k]].events); blink_usmark(b);
    }
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
