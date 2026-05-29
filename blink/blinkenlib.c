#include "blink/blinkenlib.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blink/bus.h"
#include "blink/dis.h"
#include "blink/endian.h"
#include "blink/high.h"
#include "blink/loader.h"
#include "blink/machine.h"
#include "blink/map.h"
#include "blink/syscall.h"
#include "blink/x86.h"

void update_clstruct(struct Machine *m);

/*
 * program  | cpu cycles | speed on low end device
 * -----------------------------------------------
 * FASM     |   7 * 10e3 | 300ms
 * GNU AS   | 157 * 10e3 | 1s
 * GNU LD   | 215 * 10e3 | 1s
 * NASM     |1000 * 10e3 | 10s
 * ---------------------
 * MAX_CYCLES holds the max amount of cpu emulation
 * cycles before a "context switch" where execution
 * is paused, and the javascript runtime event loop
 * is allowed to resume.
 * MAX_CYCLES is set so that FASM runs uninterrupted,
 * and anything else is interrupted at least 5 times
 * per second, which is enough to have good renderer
 * updates on low end devices, despite some lag.
 */
#define MAX_CYCLES 100000

/*
 * After this max amount of context switches,
 * the process will terminate with SIGXCPU
 */
#define MAX_SWITCHES 1000

int switches_count = 0;

/*
 * This blink wrapper will communicate events with
 * the javascript side via SIGTRAP signals and the
 * additional SIGTRAP event codes.
 * The event codes are defined here. An event code
 * of 0 will be recognized as an actuall SIGTRAP.
 */
#define SIGTRAP_CODE_SIGTRAP  0
#define SIGTRAP_CODE_PREEMPT  40
#define SIGTRAP_CODE_STEP     41
#define SIGTRAP_CODE_FAKE_TTY 42

/*
 * These variables are defined by javascript;
 * the pointers are passed to main when this module starts
 */
void (*signal_callback)(int, int) = 0;
void (*exit_callback)(int) = 0;

/*
 * this buffer holds the disassembly strings
 * that will be passed to js
 */
#define DIS_MAX_LINES    200
#define DIS_MAX_LINE_LEN 200
char dis_buffer[DIS_MAX_LINES][DIS_MAX_LINE_LEN] = {0};

/*
 * These buffers hold the program execution arguments.
 * The pointers to these strings will be passed to js,
 * and the content will be dynamically set by js
 */
#define ARGC_MAX_LINE_LEN     4096
#define ARGV_MAX_LINE_LEN     4096
#define PROGNAME_MAX_LINE_LEN 1024
#define ARGC_MAX_ARGS         256
char argc_string[ARGC_MAX_LINE_LEN] = {0};
char argv_string[ARGV_MAX_LINE_LEN] = {0};
char progname_string[PROGNAME_MAX_LINE_LEN] = {0};

struct clstruct cls;
// Thread-local so each VM thread (X server on one pthread, X client on another)
// has its own current (m,s) — Actor() sets the global `m`, and the main thread's
// vm_spawn/SetUp also touches them, so without per-thread storage the two VM
// threads would clobber each other's machine pointers (server corruption).
_Thread_local struct System *s;
_Thread_local struct Machine *m;

/*
 * Framebuffer registration published by the guest.
 * The guest (e.g. an fbdev X server or a direct-render app) registers the
 * guest virtual address and geometry of its RGBA framebuffer via the
 * synthetic syscall SYS_blinkenlib_fb_register (see syscall.c). The host
 * then reads the geometry with the blinkenlib_get_fb_* getters and maps the
 * pixels zero-copy through blinkenlib_spy_address(fb_vaddr). fb_generation is
 * bumped on every registration and on every guest-signalled flip so the host
 * can skip blits when nothing changed.
 */
u64 fb_vaddr = 0;
u32 fb_width = 0;
u32 fb_height = 0;
u32 fb_stride = 0;   /* bytes per row; 0 means width*4 */
u32 fb_generation = 0;

/*
 * Input event ring buffer (host -> guest).
 *
 * The JS host pushes keyboard/mouse events with blinkenlib_push_input(); the
 * guest drains them via the synthetic syscall SYS_blinkenlib_input_read
 * (0x5fc), which copies up to N packed 16-byte events into a guest buffer and
 * returns the count. This is the input counterpart to the framebuffer path:
 * host produces, guest consumes, no shared-memory polling required on the
 * guest side. The packed event layout MUST match the guest's struct:
 *   struct blinkenlib_input_event { u16 type; u16 code; i32 x; i32 y;
 *                                   i32 value; u32 _pad; }  // 16 bytes
 * type: 1=key, 2=motion, 3=button. For key/button, code=keycode/button and
 * value=1(down)/0(up). For motion, x/y hold absolute guest coords.
 */
#define BLINKENLIB_INPUT_RING 256  /* power-of-two event slots */
#define BLINKENLIB_INPUT_EVSZ 16   /* bytes per packed event */
static u8 input_ring[BLINKENLIB_INPUT_RING * BLINKENLIB_INPUT_EVSZ];
static u32 input_head = 0;  /* next slot the host writes */
static u32 input_tail = 0;  /* next slot the guest reads */
static struct Dis dis[1];
bool single_stepping = false;
bool debugger_enabled = false;

/**
 * Signals handler.
 * Signals will be passed to the javascript runtime.
 * SIGTRAP will not terminate the program
 */
void TerminateSignal(struct Machine *m, int sig, int code) {
#ifdef DEBUG
  if (sig != SIGTRAP) {
    printf("Terminate signal received! %d : %d \n", sig, code);
  } else {
    printf("SIGTRAP received\n");
  }
#endif
  update_clstruct(m);
  if (signal_callback) {
    signal_callback(sig, code);
  }
}

/* -------------------- */
/* Utility functions    */
/* -------------------- */

/**
 * Returns true if 𝑣 is a shadow memory virtual address.
 */
static bool IsShadow(i64 v) {
  return 0x7fff8000 <= v && v < 0x100080000000;
}

/**
 * disassemble n lines of code, starting from the current ip.
 * the disassembled lines will be stored in the dis struct.
 */
static i64 Disassemble(void) {
  i64 lines = DIS_MAX_LINES;
  if (Dis(dis, m, GetPc(m), m->ip, lines) != -1) {
    return DisFind(dis, GetPc(m));
  } else {
    return -1;
  }
}

/**
 * get the index in the dis struct at which
 * the current instruction is stored.
 * if it's not there, the dis struct is repopulated
 * by a new run of the disassembler
 */
static i64 GetDisIndex(void) {
  i64 i;
  if ((i = DisFind(dis, GetPc(m) - m->oplen)) != -1 ||
      (i = Disassemble()) != -1) {
    while (i + 1 < dis->ops.i) {
      if (!dis->ops.p[i].size) {
        ++i;
      } else {
        break;
      }
    }
  }
  return i;
}

/**
 * Populate a buffer with the ascii disassembly listing updated to
 * the current ip.
 * The buffer is designed to be read from js, and parsed into html.
 */
u64 updateDisassembler() {
  u64 lineIndex = GetDisIndex();
  for (int i = 0; i < dis->ops.i && i < DIS_MAX_LINES; i++) {
    const char *curr = DisGetLine(dis, m, i);
    int len = strlen(curr) + 1;
    if (len > DIS_MAX_LINE_LEN) {
      len = DIS_MAX_LINE_LEN;
    }
    memcpy(dis_buffer[i], curr, len);
    dis_buffer[i][len - 1] = 0;
  }
  return lineIndex;
}

void update_clstruct(struct Machine *m) {
  if (!debugger_enabled) return;
  // memory regions
  u64 pc = GetPc(m);
  u64 sp = Read64(m->sp);
  cls.codemem = (u32)SpyAddress(m, pc);
  cls.stackmem = (u32)SpyAddress(m, sp);
  // read or writes
  cls.readaddr = 0;
  cls.readsize = 0;
  cls.writeaddr = 0;
  cls.writesize = 0;
  if (!IsShadow(m->readaddr) && !IsShadow(m->readaddr + m->readsize)) {
    cls.readaddr = (u32)&m->readaddr;
    cls.readsize = (u32)&m->readsize;
  }
  if (!IsShadow(m->writeaddr) && !IsShadow(m->writeaddr + m->writesize)) {
    cls.writeaddr = (u32)&m->writeaddr;
    cls.writesize = (u32)&m->writesize;
  }

  // flags and other useful info
  cls.flags = (u32)&m->flags;
  cls.cs__base = (u32)&m->cs.base;

  // registers
  cls.rip = (u32)&m->ip;
  cls.rsp = (u32)&m->sp;
  cls.rbp = (u32)&m->bp;
  cls.rsi = (u32)&m->si;
  cls.rdi = (u32)&m->di;
  cls.r8 = (u32)&m->r8;
  cls.r9 = (u32)&m->r9;
  cls.r10 = (u32)&m->r10;
  cls.r11 = (u32)&m->r11;
  cls.r12 = (u32)&m->r12;
  cls.r13 = (u32)&m->r13;
  cls.r14 = (u32)&m->r14;
  cls.r15 = (u32)&m->r15;

  cls.rax = (u32)&m->ax;
  cls.rbx = (u32)&m->bx;
  cls.rcx = (u32)&m->cx;
  cls.rdx = (u32)&m->dx;

  // disassembled code buffer
  // TODO: all this data should be in a global
  // disassembler struct, this function should
  // only copy pointers.
  cls.dis__max_lines = DIS_MAX_LINES;
  cls.dis__max_line_len = DIS_MAX_LINE_LEN;
  cls.dis__current_line = updateDisassembler();
  cls.dis__buffer = (u32)&dis_buffer;

  // TODO: other useful data
  //  printf("page tables:\n%s\n", FormatPml4t(m));
  //  u64 entry = FindPageTableEntry(m, (GetPc(m) & -4096));
  //  printf("pagetable %lx: %lx\n", GetPc(m), entry);
}

void runLoop() {
  int interrupt;
  m->nofault = false;

  // TODO: update global disassember struct with
  // a function call. both the struct and fcall dont
  // exist right now

  if (!(interrupt = sigsetjmp(m->onhalt, 1))) {
    m->canhalt = true;
    for (int i = 0; i < MAX_CYCLES; i++) {
      LoadInstruction(m, GetPc(m));  // not really needed like this
      ExecuteInstruction(m);

      // this check should be replaced with actual breakpoints logic
      // when breakpoints are implemented
      if (single_stepping) {
        TerminateSignal(m, SIGTRAP, SIGTRAP_CODE_STEP);
        return;
      }
    }

    // send the preemption signal, passing the execution back to
    // javascript so that the JS event loop can resume. After a
    // rerender on the main thread JS will call preempt_resume()
    // and pass execution back to this routine.
    switches_count += 1;
    if (switches_count > MAX_SWITCHES) {
      TerminateSignal(m, SIGXCPU, 0);
    } else {
      TerminateSignal(m, SIGTRAP, SIGTRAP_CODE_PREEMPT);
    }

    // TODO: make the loop run a fixed num of instructions,
    // then from here use the emscripten loop features
    // to schedule a recursive call to runLoop that won't block
    // the thread
  } else {
    // if sigsetjmp fake-returned 1, the actual trap number might have been
    // either 1 or 0; this should have been stored in m->trapno
    if (interrupt == 1) interrupt = m->trapno;
#ifdef DEBUG
    printf("handling machine interrupt: %d \n", interrupt);
    puts("--");
#endif
    if (interrupt == kMachineExitTrap) {
      if (signal_callback) {
        update_clstruct(m);
        exit_callback(m->system->exitcode);
      }
    } else if (interrupt == kMachineFakeTTYtrap) {
      update_clstruct(m);
      TerminateSignal(m, SIGTRAP, SIGTRAP_CODE_FAKE_TTY);
    }
  }
  m->canhalt = false;
}

void SetUp(void) {
#ifdef __EMSCRIPTEN__
  // Env-gated syscall trace: BLINK_STRACE=<n> raises FLAG_strace so the X-server
  // diagnostic can see which syscall Xvfb loops on while it eats the heap.
  {
    extern int FLAG_strace;
    const char *st = getenv("BLINK_STRACE");
    if (st && *st) {
      extern void LogInit(const char *);
      FLAG_strace = atoi(st);
      LogInit("/em-strace.log");  // MEMFS: cross-thread coherent, host-readable
    }
  }
#endif
  InitMap();
  InitBus();
  s = NewSystem(XED_MACHINE_MODE_LONG);
  m = g_machine = NewMachine(s, 0);
  m->metal = false;
  // when true, read(0) will halt the machine, with a SIGTRAP_CODE_FAKE_TTY
  // To resume the machine, a call to blinkenlib_faketty_resume is required
  m->fakettycanhalt = true;
  // when true, guest exit syscalls will generate an interrupt that
  // can be handled via sigsetjmp, instead of calling the native _exit().
  // see: blinkenlib.c:runLoop()
  m->system->trapexit = true;

  // reset the counter we use to limit the execution cycles of a program
  switches_count = 0;

#ifdef __EMSCRIPTEN__
  // Reset the in-VM fork accounting per top-level program so each runElf treats
  // its own first fork() as the (tolerated-ENOSYS) startup daemonize fork. The
  // nested child machines created by EmRunChildInline do NOT call SetUp, so the
  // fork depth/stack is preserved across nesting levels within one run.
  { extern int g_em_fork_total, g_em_fork_depth; g_em_fork_total = 0; g_em_fork_depth = 0; }
#endif

  // TODO: from blinkenlights. define these callbacks
  //  m->system->redraw = Redraw;
  //  m->system->onbinbase = OnBinbase;
  //  m->system->onlongbranch = OnLongBranch;
}

// callback
void OnSymbols(struct System *s) {
  // ResolveBreakpoints();
  // ResolveWatchpoints();
}

void PostLoadSetup() {
  AddStdFd(&m->system->fds, 0);
  AddStdFd(&m->system->fds, 1);
  AddStdFd(&m->system->fds, 2);
  if (debugger_enabled) {
    // initialize the disassembler
    m->system->dis = dis;
    m->system->onsymbols = OnSymbols;
    LoadDebugSymbols(m->system);
    Disassemble();
  }
}

void TearDown(void) {
  // TODO: make sure free is ok when not allocated
  DisFree(dis);
  FreeMachine(m);
  memset(dis_buffer, 0, sizeof(dis_buffer));
}

/*
 * Parse a NUL-separated argv buffer into an argv array.
 * The buffer holds each argument terminated by '\0', with the
 * whole list terminated by an empty argument (a second '\0').
 * This preserves spaces inside arguments, unlike the previous
 * space-splitting scheme which broke any multi-word argument.
 * maxLen bounds how far into the buffer we will read.
 */
void stringToArgsArray(char *argsString, char **argsArray, int maxLen) {
  int count = 0;
  int i = 0;
  while (i < maxLen && argsString[i] != '\0' && count < ARGC_MAX_ARGS - 1) {
    argsArray[count++] = &argsString[i];
    while (i < maxLen && argsString[i] != '\0') i++;
    i++;  // step over the terminating NUL
  }
  argsArray[count] = NULL;
}

/**
 * Set up a program using the arguments previously set
 * by javascript in the global strings:
 * - progname_string
 * - argc_string
 * - argv_string
 *
 */
void setupProgram(bool withdebugger) {
  debugger_enabled = withdebugger;

  // terminal prompt
  printf("\n$ %s\n", argc_string);

  // get **argc
  char *args[ARGC_MAX_LINE_LEN];
  char argc_string_copy[ARGC_MAX_LINE_LEN];
  memcpy(argc_string_copy, argc_string, ARGC_MAX_LINE_LEN);
  stringToArgsArray(argc_string_copy, args, ARGC_MAX_LINE_LEN);

  // get **argv
  // TODO
  char *vars = 0;

  // close previous instances
  TearDown();
  SetUp();
  char *bios = 0;
  LoadProgram(m, progname_string, progname_string, args, &vars, bios);
  PostLoadSetup();
  update_clstruct(m);
}

/* -------------------- */
/* Exported api         */
/* -------------------- */

// ---- Concurrent VMs (e.g. X server + X client sharing the in-process MEMFS +
// AF_UNIX socket registry) -------------------------------------------------
// blinkenlib runs one (m,s) at a time, but the host can multiplex several
// cooperatively: snapshot the current VM, set up/run another, and switch back.
// A VM handle is just the (m,s) pair; the MEMFS and the unixsock/epoll shims are
// process-global, so two VMs share files and can connect to each other's
// sockets. The host pumps each VM's preempt slices (blinkenlib_preempt_resume)
// and switches the active VM with blinkenlib_vm_set between slices.
struct EmVm { struct Machine *m; struct System *s; int vmid; };
// Set by the in-process unix-socket shim's compilation unit; we tag each VM so a
// close() in one VM does not free another VM's socket entry (guest fd numbers
// collide across concurrent VMs). See blink/unixsock_shim.c.
extern _Thread_local int g_blink_unixsock_vmid;
static int g_em_next_vmid = 0;

EMSCRIPTEN_KEEPALIVE
void *blinkenlib_vm_current(void) {
  struct EmVm *h = (struct EmVm *)malloc(sizeof(struct EmVm));
  h->m = m; h->s = s; h->vmid = g_blink_unixsock_vmid;
  return h;
}

EMSCRIPTEN_KEEPALIVE
void blinkenlib_vm_set(void *handle) {
  struct EmVm *h = (struct EmVm *)handle;
  m = h->m; s = h->s; g_machine = h->m;
  g_blink_unixsock_vmid = h->vmid;
}

// Set up a NEW program in a FRESH (m,s) WITHOUT tearing down the current VM, so
// the caller can keep the previous VM alive concurrently. Returns a handle to
// the new VM (already current). Uses the same progname_string/argc_string the
// host wrote, mirroring setupProgram() minus TearDown().
EMSCRIPTEN_KEEPALIVE
void *blinkenlib_vm_spawn(int withdebugger) {
  debugger_enabled = withdebugger;
  printf("\n$ %s\n", argc_string);
  char *args[ARGC_MAX_LINE_LEN];
  char argc_string_copy[ARGC_MAX_LINE_LEN];
  memcpy(argc_string_copy, argc_string, ARGC_MAX_LINE_LEN);
  stringToArgsArray(argc_string_copy, args, ARGC_MAX_LINE_LEN);
  char *vars = 0;
  char *bios = 0;
  // SetUp() allocates a fresh (m,s) into the globals without freeing the old.
  SetUp();
  // Assign this VM a distinct id so its unix-socket entries are isolated from
  // the other concurrent VM's (close() is VM-scoped).
  g_blink_unixsock_vmid = ++g_em_next_vmid;
  // TEMP DIAG: force-trace the SERVER VM (id 1) to MEMFS so we can see why dix
  // closes the accepted client without reading it.
  if (g_blink_unixsock_vmid == 1) {
    extern int FLAG_strace; extern void LogInit(const char *);
    FLAG_strace = 2; LogInit("/em-strace.log");
  }
  LoadProgram(m, progname_string, progname_string, args, &vars, bios);
  PostLoadSetup();
  update_clstruct(m);
  return blinkenlib_vm_current();
}

// Run a VM on its OWN pthread (Web Worker under -pthread). The thread shares the
// process memory/MEMFS/fds/g_socks with the main thread + other VM threads, so
// an X server thread and an X client thread can talk over the in-process AF_UNIX
// socket while EACH uses normal BLOCKING syscalls (its own thread blocks; real
// preemptive scheduling interleaves them). The status is stored for the host to
// read; trapexit makes the guest exit longjmp to this thread's sigsetjmp instead
// of _exit()ing the whole process.
extern void Actor(struct Machine *);
struct EmThreadArg { struct Machine *m; struct System *s; int slot; int vmid; };
volatile int g_em_thread_status[8];   // by slot
volatile int g_em_thread_done[8];

static void *EmVmThread(void *argp) {
  struct EmThreadArg *a = (struct EmThreadArg *)argp;
  int slot = a->slot;
  int rc;
  struct Machine *cm = a->m;
  struct System *cs = a->s;
  int cvmid = a->vmid;
  free(a);
  g_machine = cm;
  // m/s are thread-local; set this worker thread's pointers so blinkenlib
  // helpers + the trapexit/clstruct paths operate on THIS VM (they were NULL on
  // a freshly-created pthread, which crashed the guest before it could connect).
  m = cm; s = cs;
  // Per-thread current-vmid for the in-process unix layer: the listener-readable
  // and close VM-scoping checks must use THIS thread's VM, not whatever vmid the
  // main thread left in the (now thread-local) global after spawning.
  g_blink_unixsock_vmid = cvmid;
  // Marker in shared MEMFS (cross-thread coherent, unlike the stdout callbacks)
  // so the host can confirm THIS thread actually started running its guest.
  { char p[32]; snprintf(p, sizeof(p), "/em-thr-%d.run", slot);
    FILE *mk = fopen(p, "w"); if (mk) { fputs("started\n", mk); fclose(mk); } }
  cm->thread = pthread_self();
  cs->trapexit = true;
  if (!(rc = sigsetjmp(cm->onhalt, 1))) {
    cm->canhalt = true;
    Actor(cm);  // runs until the guest halts (longjmp back here)
  }
  g_em_thread_status[slot & 7] = (cs->exited ? cs->exitcode : 0);
  g_em_thread_done[slot & 7] = 1;
  return 0;
}

// Launch the given VM handle on a new pthread in tracking `slot`. Returns 0 ok.
EMSCRIPTEN_KEEPALIVE
int blinkenlib_run_thread_slot(void *handle, int slot) {
  struct EmVm *h = (struct EmVm *)handle;
  struct EmThreadArg *a = (struct EmThreadArg *)malloc(sizeof(*a));
  pthread_t t;
  a->m = h->m; a->s = h->s; a->slot = slot; a->vmid = h->vmid;
  g_em_thread_done[slot & 7] = 0; g_em_thread_status[slot & 7] = 0;
  if (pthread_create(&t, 0, EmVmThread, a) != 0) { free(a); return -1; }
  pthread_detach(t);
  return 0;
}
EMSCRIPTEN_KEEPALIVE
int blinkenlib_run_thread(void *handle) { return blinkenlib_run_thread_slot(handle, 0); }

EMSCRIPTEN_KEEPALIVE
int blinkenlib_thread_done(void) { return g_em_thread_done[0]; }

EMSCRIPTEN_KEEPALIVE
int blinkenlib_thread_status(void) { return g_em_thread_status[0]; }

EMSCRIPTEN_KEEPALIVE
int blinkenlib_thread_done_slot(int slot) { return g_em_thread_done[slot & 7]; }

EMSCRIPTEN_KEEPALIVE
int blinkenlib_thread_status_slot(int slot) { return g_em_thread_status[slot & 7]; }

EMSCRIPTEN_KEEPALIVE
void blinkenlib_run_fast() {
  setupProgram(false);
  single_stepping = false;
  runLoop();
}

EMSCRIPTEN_KEEPALIVE
void blinkenlib_run() {
  setupProgram(true);
  // run the program to the end
  single_stepping = false;
  runLoop();
}

EMSCRIPTEN_KEEPALIVE
void blinkenlib_starti() {
  setupProgram(true);
  // don't run any instruction
}

EMSCRIPTEN_KEEPALIVE
void blinkenlib_start() {
  setupProgram(true);
  // TODO: set breakpoint at main
  single_stepping = false;
  runLoop();
}

EMSCRIPTEN_KEEPALIVE
void blinkenlib_stepi() {
  if (s->exited) {
    unassert(!"Invalid state");
  }
  // run a single step
  single_stepping = true;
  runLoop();
}

EMSCRIPTEN_KEEPALIVE
void blinkenlib_continue() {
  if (s->exited) {
    unassert(!"Invalid state");
  }
  single_stepping = false;
  runLoop();
}

EMSCRIPTEN_KEEPALIVE
void blinkenlib_preempt_resume() {
  if (s->exited) {
    unassert(!"Invalid state");
  }
  runLoop();
}

EMSCRIPTEN_KEEPALIVE
void blinkenlib_faketty_resume() {
  if (s->exited) {
    unassert(!"Invalid state");
  }
  if (!m->fakettycanhalt) {
    unassert(!"Invalid state (tty)");
  }
  m->fakettycanhalt = false;
  runLoop();
}

EMSCRIPTEN_KEEPALIVE
void *blinkenlib_get_clstruct() {
  return &cls;
}

EMSCRIPTEN_KEEPALIVE
void *blinkenlib_get_argc_string() {
  return &argc_string;
}

EMSCRIPTEN_KEEPALIVE
void *blinkenlib_get_argv_string() {
  return &argv_string;
}

EMSCRIPTEN_KEEPALIVE
void *blinkenlib_get_progname_string() {
  return &progname_string;
}

EMSCRIPTEN_KEEPALIVE
u8 *blinkenlib_spy_address(u64 virtual_address) {
  BEGIN_NO_PAGE_FAULTS;
  return SpyAddress(m, virtual_address);
  END_NO_PAGE_FAULTS;
}

/* -------------------- */
/* Framebuffer getters  */
/* -------------------- */

EMSCRIPTEN_KEEPALIVE
u64 blinkenlib_get_fb_vaddr(void) { return fb_vaddr; }

EMSCRIPTEN_KEEPALIVE
u32 blinkenlib_get_fb_width(void) { return fb_width; }

EMSCRIPTEN_KEEPALIVE
u32 blinkenlib_get_fb_height(void) { return fb_height; }

EMSCRIPTEN_KEEPALIVE
u32 blinkenlib_get_fb_stride(void) {
  return fb_stride ? fb_stride : fb_width * 4;
}

EMSCRIPTEN_KEEPALIVE
u32 blinkenlib_get_fb_generation(void) { return fb_generation; }

/*
 * Host pointer to the start of the registered framebuffer, or 0 if the guest
 * has not registered one yet. Convenience wrapper over spy_address(fb_vaddr).
 */
EMSCRIPTEN_KEEPALIVE
u8 *blinkenlib_get_fb_ptr(void) {
  if (!fb_vaddr || !m) return 0;
  BEGIN_NO_PAGE_FAULTS;
  return SpyAddress(m, fb_vaddr);
  END_NO_PAGE_FAULTS;
}

/* -------------------- */
/* Input event device   */
/* -------------------- */

/*
 * Host pushes one input event into the ring. Called from JS via
 * blinkenlib_push_input(type, code, x, y, value). If the ring is full the
 * oldest event is dropped (advance tail) so the most recent input always
 * lands -- a stuck/slow guest must not wedge the host.
 */
EMSCRIPTEN_KEEPALIVE
void blinkenlib_push_input(u32 type, u32 code, i32 x, i32 y, i32 value) {
  u8 *slot = input_ring + (input_head % BLINKENLIB_INPUT_RING) * BLINKENLIB_INPUT_EVSZ;
  u16 t16 = (u16)type, c16 = (u16)code;
  memcpy(slot + 0, &t16, 2);
  memcpy(slot + 2, &c16, 2);
  memcpy(slot + 4, &x, 4);
  memcpy(slot + 8, &y, 4);
  memcpy(slot + 12, &value, 4);
  input_head++;
  /* If head laps tail the buffer is full; drop the oldest. */
  if (input_head - input_tail > BLINKENLIB_INPUT_RING) {
    input_tail = input_head - BLINKENLIB_INPUT_RING;
  }
}

/* Number of unread events currently queued. */
EMSCRIPTEN_KEEPALIVE
u32 blinkenlib_input_pending(void) { return input_head - input_tail; }

/*
 * Drain up to max_events into the guest buffer at gva (guest virtual addr).
 * Returns the number of events written. Used by SYS_blinkenlib_input_read.
 * Each event is BLINKENLIB_INPUT_EVSZ bytes; the guest buffer must hold
 * max_events * 16 bytes. Copies through SpyAddress so it respects guest paging.
 */
int blinkenlib_input_drain(struct Machine *mm, u64 gva, u32 max_events) {
  u32 n = 0;
  if (!mm || !gva) return 0;
  while (n < max_events && input_tail != input_head) {
    u8 *src = input_ring + (input_tail % BLINKENLIB_INPUT_RING) * BLINKENLIB_INPUT_EVSZ;
    u8 *dst = SpyAddress(mm, gva + (u64)n * BLINKENLIB_INPUT_EVSZ);
    if (!dst) break;
    memcpy(dst, src, BLINKENLIB_INPUT_EVSZ);
    input_tail++;
    n++;
  }
  return (int)n;
}

EMSCRIPTEN_KEEPALIVE
int main(int argc, char *argv[]) {
#ifndef __EMSCRIPTEN__
  puts("This program is designed to run in emscripten");
  return 1;
#endif
  puts("Initializing blink emulator...");
  if (argc != 3) {
    puts("Error. main expected 3 args");
    return 1;
  }
  int signal_callback_num = atoi(argv[1]);
  int exit_callback_num = atoi(argv[2]);
  signal_callback = (void (*)(int, int))signal_callback_num;
  exit_callback = (void (*)(int))exit_callback_num;
#ifdef DEBUG
  printf("fp1: %d\n", signal_callback_num);
  printf("fp2: %d\n", exit_callback_num);
#endif
  // disable ansi colors in prints
  g_high.enabled = false;
  // initialize the cross-language struct
  cls.version = CLSTRUCT_VERSION;
  // overlays setup goes here
  // vfs setup goes here
  puts("blink ready!");
}

#ifdef __EMSCRIPTEN__
// Strong override of emscripten's host mprotect syscall stub. Emscripten leaves
// ___syscall_mprotect returning -ENOSYS and spams "unsupported syscall:
// __syscall_mprotect"; under wasm there is no page protection, so this is a
// correct success no-op. The previous failure: ENOSYS made musl/Xorg arena
// allocators retry with fresh mmaps in a loop, steadily eating the whole heap
// (the X-server smoke grew ~100MB/step to 4GB then aborted). Returning 0 lets
// the allocator settle. A strong C definition wins over emscripten's weak stub.
long __syscall_mprotect(long addr, long len, long prot) {
  (void)addr; (void)len; (void)prot;
  return 0;
}
#endif
