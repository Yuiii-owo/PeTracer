/*
 * PeTracer Windows-side agent.
 *
 * Loaded into the target process by petracer_launch.exe (CREATE_SUSPENDED +
 * remote LoadLibraryW).  It installs INT3 breakpoints on ntdll NT APIs and
 * ws2_32 entry points, handles them from a vectored exception handler and
 * emits one JSON object per line to PETRACER_EVENT_LOG.
 *
 * Hook scheme: INT3 at function entry -> VEH restores the original byte,
 * sets TF, logs, returns; the single-step exception re-arms the INT3.  This
 * needs no instruction relocation and works for arbitrarily short/odd
 * prologues (important under Wine, whose builtin prologues are not the
 * canonical Windows syscall stubs).
 */
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <wchar.h>

#ifndef EXCEPTION_BREAKPOINT
#define EXCEPTION_BREAKPOINT 0x80000003L
#endif
#ifndef EXCEPTION_SINGLE_STEP
#define EXCEPTION_SINGLE_STEP 0x80000004L
#endif

/* ------------------------------------------------------------------ */
/* minimal NT types                                                     */
/* ------------------------------------------------------------------ */
typedef struct _PT_US {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} PT_US;

typedef struct _PT_OBJA {
#ifdef _WIN64
    ULONG  Length;
    ULONG  Pad;
    HANDLE RootDirectory;
    PT_US *ObjectName;
    ULONG  Attributes;
#else
    ULONG  Length;
    HANDLE RootDirectory;
    PT_US *ObjectName;
    ULONG  Attributes;
#endif
} PT_OBJA;

typedef struct _PT_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    PT_US      FullDllName;
    PT_US      BaseDllName;
} PT_LDR_ENTRY;

typedef USHORT (WINAPI *pRtlCaptureStackBackTrace)(ULONG, ULONG, PVOID *, PULONG);

/* ------------------------------------------------------------------ */
/* globals                                                              */
/* ------------------------------------------------------------------ */
static HANDLE              g_log = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION    g_lock;
static int                 g_lock_ready;
static HINSTANCE           g_self;
static pRtlCaptureStackBackTrace g_capture;
static LONG (WINAPI *g_NtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static LONG (WINAPI *g_NtQueryKey)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static PVOID               g_main_base;
static ULONG               g_main_size;
static WCHAR               g_main_name[260];

static __thread int  t_guard;
static __thread void *t_step_addr;

#define MAX_HOOKS 64
typedef void (*hook_fn)(CONTEXT *);
typedef struct {
    const char *dll;
    const char *name;
    void       *addr;
    BYTE        orig;
    hook_fn     fn;
} hook_t;
static hook_t g_hooks[MAX_HOOKS];
static int    g_hook_count;
static int    g_hook_limit = 1000;

/* handle -> path correlation, filled at Create/Open time, resolved lazily
 * once the caller's out-parameter has been written by the API. */
#define MAX_PENDING 192
typedef struct {
    volatile LONG used;
    HANDLE       *out;          /* caller's HANDLE variable */
    int           kind;         /* 1=file 2=registry 3=process */
    DWORD         aux;          /* process id for kind==3 */
    WCHAR         path[512];
} pending_t;
static pending_t g_pending[MAX_PENDING];
static volatile LONG g_pending_seq;

/* ---- import (IAT) tracing ------------------------------------------ */
static volatile LONG g_seq;
static int g_trace_imports;
#define MAX_IMPORTS 512
typedef struct {
    char  name[96];
    char  dll[64];
    void *orig;
    void *stub;
    volatile LONG hits;
    int   crt;
} import_t;
static import_t g_imports[MAX_IMPORTS];
static int g_import_count;
static unsigned char *g_stub_mem;
static size_t g_stub_used;
static volatile LONG g_import_calls;
static volatile LONG g_import_skipped;

/* ------------------------------------------------------------------ */
/* small helpers                                                        */
/* ------------------------------------------------------------------ */
static unsigned long long now_ms(void)
{
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return (u.QuadPart - 116444736000000000ULL) / 10000ULL;
}

static int safe_read(void *dst, const void *src, size_t n)
{
    uintptr_t p, end;
    if (!src || !n || n > 0x1000000)
        return 0;
    p = (uintptr_t)src;
    end = p + n;
    if (end < p)
        return 0;
    while (p < end) {
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t region_end;
        DWORD prot;
        if (!VirtualQuery((LPCVOID)p, &mbi, sizeof(mbi)))
            return 0;
        if (mbi.State != MEM_COMMIT)
            return 0;
        prot = mbi.Protect & 0xff;
        if ((mbi.Protect & PAGE_GUARD) || prot == PAGE_NOACCESS)
            return 0;
        region_end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (region_end <= p)
            return 0;
        p = region_end;
    }
    memcpy(dst, src, n);
    return 1;
}

static void wcopy(WCHAR *dst, size_t cap, const WCHAR *src, int maxw)
{
    size_t i;
    if (!cap)
        return;
    if (!src) { dst[0] = 0; return; }
    for (i = 0; i + 1 < cap && src[i]; i++) {
        if (maxw >= 0 && (int)i >= maxw) break;
        dst[i] = src[i];
    }
    dst[i] = 0;
}

static void us_to_w(PWSTR buf, size_t cap, const PT_US *us)
{
    if (!cap) return;
    buf[0] = 0;
    if (!us || !us->Buffer || !us->Length) return;
    {
        size_t chars = us->Length / sizeof(WCHAR);
        if (chars > cap - 1) chars = cap - 1;
        if (!safe_read(buf, us->Buffer, chars * sizeof(WCHAR))) { buf[0] = 0; return; }
        buf[chars] = 0;
    }
}

static void wappend(WCHAR *dst, size_t cap, const WCHAR *src)
{
    size_t len, i = 0;
    if (!cap || !src) return;
    len = wcslen(dst);
    if (len >= cap) return;
    while (len + 1 < cap && src[i]) dst[len++] = src[i++];
    dst[len] = 0;
}

static void ntpath_to_dos(const WCHAR *in, WCHAR *out, size_t cap)
{
    if (!cap) return;
    out[0] = 0;
    if (!in) return;
    if (wcslen(in) >= 4 && in[0] == '\\' && in[1] == '?' && in[2] == '?' && in[3] == '\\')
        in += 4;
    else if (wcslen(in) >= 4 && in[0] == '\\' && in[1] == '\\' && in[2] == '?' && in[3] == '\\')
        in += 4;
    if (wcslen(in) >= 4 && _wcsnicmp(in, L"UNC\\", 4) == 0) {
        wappend(out, cap, L"\\\\");
        wappend(out, cap, in + 4);
    } else {
        wcopy(out, cap, in, -1);
    }
}

static PPEB pt_peb(void)
{
#ifdef _WIN64
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}

static PT_LDR_ENTRY *first_module(void)
{
    PPEB peb = pt_peb();
    PLIST_ENTRY head;
    if (!peb || !peb->Ldr) return NULL;
    head = &peb->Ldr->InMemoryOrderModuleList;
    if (head->Flink == head) return NULL;
    return (PT_LDR_ENTRY *)CONTAINING_RECORD(head->Flink, PT_LDR_ENTRY, InMemoryOrderLinks);
}

static int module_for_addr(ULONG64 addr, WCHAR *name, size_t cap,
                           PVOID *base_out, PULONG size_out)
{
    PPEB peb = pt_peb();
    PLIST_ENTRY head, e;
    if (!peb || !peb->Ldr) return 0;
    head = &peb->Ldr->InMemoryOrderModuleList;
    for (e = head->Flink; e && e != head; e = e->Flink) {
        PT_LDR_ENTRY *m = (PT_LDR_ENTRY *)CONTAINING_RECORD(e, PT_LDR_ENTRY, InMemoryOrderLinks);
        uintptr_t b = (uintptr_t)m->DllBase;
        if (addr >= b && addr < b + m->SizeOfImage) {
            if (name) us_to_w(name, cap, &m->BaseDllName);
            if (base_out) *base_out = m->DllBase;
            if (size_out) *size_out = m->SizeOfImage;
            return 1;
        }
    }
    return 0;
}

static int stack_in_main(CONTEXT *c)
{
    PVOID frames[16];
    USHORT n, i;
    (void)c;
    if (!g_capture || !g_main_base) return 0;
    n = g_capture(1, 16, frames, NULL);
    for (i = 0; i < n; i++) {
        uintptr_t a = (uintptr_t)frames[i];
        if (a >= (uintptr_t)g_main_base && a < (uintptr_t)g_main_base + g_main_size)
            return 1;
    }
    return 0;
}

static ULONG64 return_address(CONTEXT *c)
{
#ifdef _WIN64
    return *(ULONG64 *)c->Rsp;
#else
    return *(ULONG32 *)c->Esp;
#endif
}

static ULONG64 arg(CONTEXT *c, int n)
{
#ifdef _WIN64
    switch (n) {
    case 1: return c->Rcx;
    case 2: return c->Rdx;
    case 3: return c->R8;
    case 4: return c->R9;
    default: return *(ULONG64 *)(c->Rsp + 0x28 + (ULONG64)(n - 5) * 8);
    }
#else
    return *(ULONG32 *)(c->Esp + 4 + (n - 1) * 4);
#endif
}

static unsigned long arg32(CONTEXT *c, int n)
{
    return (unsigned long)(arg(c, n) & 0xFFFFFFFFu);
}

static int attr_path(ULONG64 attr_ptr, WCHAR *out, size_t cap)
{
    PT_OBJA oa;
    PT_US us;
    WCHAR raw[1024];
    out[0] = 0;
    if (!attr_ptr) return 0;
    if (!safe_read(&oa, (void *)attr_ptr, sizeof(oa))) return 0;
    if (!oa.ObjectName || !safe_read(&us, oa.ObjectName, sizeof(us))) return 0;
    if (!us.Buffer || !us.Length) return 0;
    us_to_w(raw, 1024, &us);
    ntpath_to_dos(raw, out, cap);
    return 1;
}

/* ------------------------------------------------------------------ */
/* JSON event builder                                                   */
/* ------------------------------------------------------------------ */
typedef struct {
    char  *p;
    size_t n;
    size_t cap;
    int    ok;
} evb;

static void sb_init(evb *b, char *buf, size_t cap)
{
    b->p = buf; b->n = 0; b->cap = cap; b->ok = cap > 0;
    if (cap) buf[0] = 0;
}

static void sb_raw(evb *b, const char *s, size_t n)
{
    if (!b->ok) return;
    if (b->n + n + 1 > b->cap) { b->ok = 0; return; }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = 0;
}


static void sb_printf(evb *b, const char *fmt, ...)
{
    va_list ap;
    int n;
    if (!b->ok) return;
    va_start(ap, fmt);
    n = vsnprintf(b->p + b->n, b->cap - b->n, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= b->cap - b->n) { b->ok = 0; return; }
    b->n += (size_t)n;
}

static void sb_json_str(evb *b, const char *s)
{
    const unsigned char *p;
    if (!s) { sb_raw(b, "null", 4); return; }
    sb_raw(b, "\"", 1);
    for (p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"':  sb_raw(b, "\\\"", 2); break;
        case '\\': sb_raw(b, "\\\\", 2); break;
        case '\n': sb_raw(b, "\\n", 2); break;
        case '\r': sb_raw(b, "\\r", 2); break;
        case '\t': sb_raw(b, "\\t", 2); break;
        default:
            if (*p < 0x20) sb_printf(b, "\\u%04x", *p);
            else sb_raw(b, (const char *)p, 1);
        }
    }
    sb_raw(b, "\"", 1);
}

static void sb_json_wstr(evb *b, const WCHAR *w)
{
    char tmp[4096];
    int n;
    if (!w) { sb_raw(b, "null", 4); return; }
    n = WideCharToMultiByte(CP_UTF8, 0, w, -1, tmp, sizeof(tmp), NULL, NULL);
    if (n <= 0) { sb_raw(b, "\"\"", 2); return; }
    sb_json_str(b, tmp);
}

static void write_line(const char *s, size_t n)
{
    DWORD wrote;
    int old;
    if (g_log == INVALID_HANDLE_VALUE || !g_lock_ready || !n) return;
    EnterCriticalSection(&g_lock);
    old = t_guard;
    t_guard = 1;
    WriteFile(g_log, s, (DWORD)n, &wrote, NULL);
    t_guard = old;
    LeaveCriticalSection(&g_lock);
}


static void ev_base(evb *b, char *buf, size_t cap)
{
    sb_init(b, buf, cap);
    sb_printf(b, "{\"seq\":%ld,\"ts\":%llu,\"pid\":%lu,\"tid\":%lu",
              (long)InterlockedIncrement(&g_seq), now_ms(),
              (unsigned long)GetCurrentProcessId(),
              (unsigned long)GetCurrentThreadId());
}

static void ev_init(evb *b, char *buf, size_t cap, const char *type,
                    const char *api, CONTEXT *c)
{
    WCHAR caller[64];
    ULONG64 ra;
    int in_main;
    ev_base(b, buf, cap);
    caller[0] = 0;
    ra = return_address(c);
    module_for_addr(ra, caller, 64, NULL, NULL);
    in_main = stack_in_main(c);
    sb_printf(b, ",\"type\":\"%s\",\"api\":\"%s\",\"caller\":", type, api);
    sb_json_wstr(b, caller);
    sb_printf(b, ",\"origin\":\"%s\"", in_main ? "sample" : "system");
}

static void ev_end(evb *b)
{
    if (!b->ok) return;
    sb_raw(b, "}\n", 2);
    if (b->ok) write_line(b->p, b->n);
}

static void ev_strw(evb *b, const char *key, const WCHAR *v)
{
    sb_printf(b, ",\"%s\":", key);
    sb_json_wstr(b, v);
}

static void ev_stra(evb *b, const char *key, const char *v)
{
    sb_printf(b, ",\"%s\":", key);
    sb_json_str(b, v);
}

static void ev_num(evb *b, const char *key, unsigned long long v)
{
    sb_printf(b, ",\"%s\":%llu", key, v);
}

static void ev_hex(evb *b, const char *key, unsigned long long v)
{
    sb_printf(b, ",\"%s\":\"0x%llx\"", key, v);
}


/* ------------------------------------------------------------------ */
/* import (IAT) tracing                                                 */
/* ------------------------------------------------------------------ */
static int is_crt_dll(const char *dll)
{
    return strstr(dll, "ucrt") || strstr(dll, "msvcrt") ||
           strstr(dll, "api-ms-win-crt") || strstr(dll, "libgcc") ||
           strstr(dll, "libstdc++");
}

static void log_import(unsigned idx, int has_args,
                       ULONG64 a1, ULONG64 a2, ULONG64 a3, ULONG64 a4)
{
    evb b;
    char buf[2048];
    import_t *imp;
    if (idx >= (unsigned)g_import_count) return;
    imp = &g_imports[idx];
    if (InterlockedIncrement(&imp->hits) > 200) {
        InterlockedIncrement(&g_import_skipped);
        return;
    }
    if (InterlockedIncrement(&g_import_calls) > 20000) {
        InterlockedIncrement(&g_import_skipped);
        return;
    }
    ev_base(&b, buf, sizeof(buf));
    sb_printf(&b, ",\"type\":\"import.call\",\"api\":");
    sb_json_str(&b, imp->name);
    sb_printf(&b, ",\"dll\":");
    sb_json_str(&b, imp->dll);
    sb_printf(&b, ",\"caller\":\"sample\",\"origin\":\"sample\"");
    if (has_args) {
        ev_hex(&b, "a1", a1);
        ev_hex(&b, "a2", a2);
        ev_hex(&b, "a3", a3);
        ev_hex(&b, "a4", a4);
    }
    ev_end(&b);
}

#ifdef _WIN64
static void pt_import_hit(ULONG idx, ULONG64 a1, ULONG64 a2, ULONG64 a3, ULONG64 a4)
{
    log_import(idx, 1, a1, a2, a3, a4);
}
#else
static void __cdecl pt_import_hit32(ULONG idx)
{
    log_import(idx, 0, 0, 0, 0, 0);
}
#endif

static unsigned char *emit32(unsigned char *p, unsigned int v) { memcpy(p, &v, 4); return p + 4; }
static unsigned char *emit64(unsigned char *p, ULONG64 v) { memcpy(p, &v, 8); return p + 8; }

#ifdef _WIN64
static void build_stub64(unsigned char *s, int idx, void *orig)
{
    unsigned char *p = s;
    int i;
    /* save volatile arg regs + rax/r10/r11, then align */
    *p++ = 0x51;                       /* push rcx */
    *p++ = 0x52;                       /* push rdx */
    *p++ = 0x41; *p++ = 0x50;          /* push r8  */
    *p++ = 0x41; *p++ = 0x51;          /* push r9  */
    *p++ = 0x50;                       /* push rax */
    *p++ = 0x41; *p++ = 0x52;          /* push r10 */
    *p++ = 0x41; *p++ = 0x53;          /* push r11 */
    *p++ = 0x48; *p++ = 0x81; *p++ = 0xEC; emit32(p, 0xA0); p += 4; /* sub rsp,0xA0 */
    /* logger(idx, rcx, rdx, r8, r9) from saved slots */
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0x94; *p++ = 0x24; emit32(p, 0xD0); p += 4; /* mov rdx,[rsp+0xD0] */
    *p++ = 0x4C; *p++ = 0x8B; *p++ = 0x84; *p++ = 0x24; emit32(p, 0xC8); p += 4; /* mov r8,[rsp+0xC8] */
    *p++ = 0x4C; *p++ = 0x8B; *p++ = 0x8C; *p++ = 0x24; emit32(p, 0xC0); p += 4; /* mov r9,[rsp+0xC0] */
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0x84; *p++ = 0x24; emit32(p, 0xB8); p += 4; /* mov rax,[rsp+0xB8] */
    *p++ = 0x48; *p++ = 0x89; *p++ = 0x44; *p++ = 0x24; *p++ = 0x20;             /* mov [rsp+0x20],rax */
    for (i = 0; i < 6; i++) {
        *p++ = 0x0F; *p++ = 0x11; *p++ = (unsigned char)(0x84 + i * 8); *p++ = 0x24;
        emit32(p, 0x30 + i * 0x10); p += 4;
    }
    *p++ = 0x48; *p++ = 0xB9; p = emit64(p, (ULONG64)idx);
    *p++ = 0x48; *p++ = 0xB8; p = emit64(p, (ULONG64)(uintptr_t)pt_import_hit);
    *p++ = 0xFF; *p++ = 0xD0;          /* call rax */
    for (i = 0; i < 6; i++) {
        *p++ = 0x0F; *p++ = 0x10; *p++ = (unsigned char)(0x84 + i * 8); *p++ = 0x24;
        emit32(p, 0x30 + i * 0x10); p += 4;
    }
    *p++ = 0x48; *p++ = 0x81; *p++ = 0xC4; emit32(p, 0xA0); p += 4; /* add rsp,0xA0 */
    *p++ = 0x41; *p++ = 0x5B;          /* pop r11 */
    *p++ = 0x41; *p++ = 0x5A;          /* pop r10 */
    *p++ = 0x58;                       /* pop rax */
    *p++ = 0x41; *p++ = 0x59;          /* pop r9  */
    *p++ = 0x41; *p++ = 0x58;          /* pop r8  */
    *p++ = 0x5A;                       /* pop rdx */
    *p++ = 0x59;                       /* pop rcx */
    *p++ = 0x48; *p++ = 0xB8; p = emit64(p, (ULONG64)(uintptr_t)orig);
    *p++ = 0xFF; *p++ = 0xE0;          /* jmp rax */
}
#else
static void build_stub32(unsigned char *s, int idx, void *orig)
{
    unsigned char *p = s;
    *p++ = 0x60;                                   /* pushad */
    *p++ = 0x68; p = emit32(p, (unsigned int)idx); /* push idx */
    *p++ = 0xB8; p = emit32(p, (unsigned int)(uintptr_t)pt_import_hit32);
    *p++ = 0xFF; *p++ = 0xD0;                      /* call eax */
    *p++ = 0x83; *p++ = 0xC4; *p++ = 0x04;         /* add esp,4 */
    *p++ = 0x61;                                   /* popad */
    *p++ = 0xB8; p = emit32(p, (unsigned int)(uintptr_t)orig);
    *p++ = 0xFF; *p++ = 0xE0;                      /* jmp eax */
}
#endif

static int install_imports(void)
{
    unsigned char *base = (unsigned char *)g_main_base;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_IMPORT_DESCRIPTOR *desc;
    DWORD imp_rva;
    if (!base) return 0;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    imp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!imp_rva) return 0;
    g_stub_mem = (unsigned char *)VirtualAlloc(NULL, 0x40000, MEM_COMMIT | MEM_RESERVE,
                                               PAGE_EXECUTE_READWRITE);
    if (!g_stub_mem) return 0;
    desc = (IMAGE_IMPORT_DESCRIPTOR *)(base + imp_rva);
    for (; desc->Name; desc++) {
        const char *dn = (const char *)(base + desc->Name);
        char dll[64];
        IMAGE_THUNK_DATA *iat, *intt;
        DWORD old;
        int i, n;
        if (!desc->FirstThunk || !desc->OriginalFirstThunk) continue;
        iat = (IMAGE_THUNK_DATA *)(base + desc->FirstThunk);
        intt = (IMAGE_THUNK_DATA *)(base + desc->OriginalFirstThunk);
        strncpy(dll, dn, 63);
        dll[63] = 0;
        for (n = 0; iat[n].u1.Function; n++) { }
        if (!n) continue;
        if (!VirtualProtect(iat, (n + 1) * sizeof(IMAGE_THUNK_DATA), PAGE_READWRITE, &old))
            continue;
        for (i = 0; i < n && g_import_count < MAX_IMPORTS; i++) {
            IMAGE_IMPORT_BY_NAME *ibn;
            void *orig, *stub;
            if (intt[i].u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            ibn = (IMAGE_IMPORT_BY_NAME *)(base + intt[i].u1.AddressOfData);
            if (!ibn->Name[0]) continue;
            orig = (void *)(uintptr_t)iat[i].u1.Function;
            if (!orig) continue;
            if ((uintptr_t)orig >= (uintptr_t)g_stub_mem &&
                (uintptr_t)orig < (uintptr_t)g_stub_mem + 0x40000) continue;
            if (g_stub_used + 256 > 0x40000) break;
            stub = g_stub_mem + g_stub_used;
            g_stub_used += 256;
            memset(&g_imports[g_import_count], 0, sizeof(import_t));
            strncpy(g_imports[g_import_count].name, ibn->Name, 95);
            strncpy(g_imports[g_import_count].dll, dll, 63);
            g_imports[g_import_count].orig = orig;
            g_imports[g_import_count].stub = stub;
            g_imports[g_import_count].crt = is_crt_dll(dll);
#ifdef _WIN64
            build_stub64((unsigned char *)stub, g_import_count, orig);
#else
            build_stub32((unsigned char *)stub, g_import_count, orig);
#endif
            iat[i].u1.Function = (ULONG_PTR)stub;
            g_import_count++;
        }
        VirtualProtect(iat, (n + 1) * sizeof(IMAGE_THUNK_DATA), old, &old);
    }
    if (g_import_count)
        FlushInstructionCache(GetCurrentProcess(), g_stub_mem, g_stub_used);
    return g_import_count;
}

/* ------------------------------------------------------------------ */
/* handle -> name resolution (works after the caller's frame is gone)   */
/* ------------------------------------------------------------------ */
#define PT_OBJ_NAME_INFORMATION 1
#define PT_KEY_NAME_INFORMATION 3

static int query_object_path(HANDLE h, WCHAR *out, size_t cap)
{
    unsigned char buf[4096];
    ULONG ret = 0;
    int saved;
    if (!g_NtQueryObject || !out || cap < 2) return 0;
    out[0] = 0;
    saved = t_guard;
    t_guard = 1;
    if (g_NtQueryObject(h, PT_OBJ_NAME_INFORMATION, buf, sizeof(buf), &ret) >= 0) {
        PT_US *us = (PT_US *)buf;
        if (us->Buffer && us->Length) {
            WCHAR raw[700];
            size_t chars = us->Length / sizeof(WCHAR);
            if (chars > 699) chars = 699;
            memcpy(raw, us->Buffer, chars * sizeof(WCHAR));
            raw[chars] = 0;
            ntpath_to_dos(raw, out, cap);
        }
    }
    t_guard = saved;
    return out[0] != 0;
}

static int query_key_path(HANDLE h, WCHAR *out, size_t cap)
{
    unsigned char buf[4096];
    ULONG ret = 0;
    int saved;
    if (!g_NtQueryKey || !out || cap < 2) return 0;
    out[0] = 0;
    saved = t_guard;
    t_guard = 1;
    if (g_NtQueryKey(h, PT_KEY_NAME_INFORMATION, buf, sizeof(buf), &ret) >= 0) {
        ULONG len = *(ULONG *)buf;
        if (len > 0 && len + 4 <= sizeof(buf)) {
            size_t chars = len / sizeof(WCHAR);
            if (chars > cap - 1) chars = cap - 1;
            memcpy(out, buf + 4, chars * sizeof(WCHAR));
            out[chars] = 0;
        }
    }
    t_guard = saved;
    return out[0] != 0;
}

/* ------------------------------------------------------------------ */
/* handle correlation                                                   */
/* ------------------------------------------------------------------ */
static void pending_add(HANDLE *out, int kind, const WCHAR *path, DWORD aux)
{
    LONG i = InterlockedIncrement(&g_pending_seq);
    pending_t *e = &g_pending[(ULONG)i % MAX_PENDING];
    e->used = 0;
    e->out = out;
    e->kind = kind;
    e->aux = aux;
    wcopy(e->path, 512, path, -1);
    e->used = 1;
}

static int pending_lookup(HANDLE h, int kind, WCHAR *path, size_t cap, DWORD *aux)
{
    int i;
    if (!h) return 0;
    for (i = 0; i < MAX_PENDING; i++) {
        pending_t *e = &g_pending[i];
        HANDLE v = NULL;
        if (!e->used || e->kind != kind || !e->out) continue;
        if (!safe_read(&v, e->out, sizeof(v))) continue;
        if (v == h) {
            wcopy(path, cap, e->path, -1);
            if (aux) *aux = e->aux;
            e->out = NULL;
            e->used = 0;
            return 1;
        }
    }
    return 0;
}

static DWORD handle_pid(HANDLE h)
{
    WCHAR path[8];
    DWORD aux = 0;
    if (!h || h == (HANDLE)(ULONG_PTR)-1) return GetCurrentProcessId();
    {
        int saved = t_guard;
        DWORD pid;
        t_guard = 1;
        pid = GetProcessId(h);
        t_guard = saved;
        if (pid) return pid;
    }
    if (pending_lookup(h, 3, path, 8, &aux)) return aux;
    return 0;
}

/* ------------------------------------------------------------------ */
/* hook handlers                                                        */
/* ------------------------------------------------------------------ */
static void h_NtCreateFile(CONTEXT *c)
{
    WCHAR path[1024];
    evb b;
    char buf[8192];
    ULONG64 disp;
    attr_path(arg(c, 3), path, 1024);
    disp = arg32(c, 8);
    pending_add((HANDLE *)(uintptr_t)arg(c, 1), 1, path, 0);
    ev_init(&b, buf, sizeof(buf), (disp == 0 || disp == 1) ? "file.open" : "file.create",
            "NtCreateFile", c);
    ev_strw(&b, "path", path);
    ev_hex(&b, "access", arg32(c, 2));
    ev_num(&b, "disposition", disp);
    ev_hex(&b, "options", arg32(c, 9));
    ev_end(&b);
}

static void h_NtOpenFile(CONTEXT *c)
{
    WCHAR path[1024];
    evb b;
    char buf[8192];
    attr_path(arg(c, 3), path, 1024);
    pending_add((HANDLE *)(uintptr_t)arg(c, 1), 1, path, 0);
    ev_init(&b, buf, sizeof(buf), "file.open", "NtOpenFile", c);
    ev_strw(&b, "path", path);
    ev_hex(&b, "access", arg32(c, 2));
    ev_end(&b);
}

static void h_NtDeleteFile(CONTEXT *c)
{
    WCHAR path[1024];
    evb b;
    char buf[8192];
    attr_path(arg(c, 1), path, 1024);
    ev_init(&b, buf, sizeof(buf), "file.delete", "NtDeleteFile", c);
    ev_strw(&b, "path", path);
    ev_end(&b);
}

static void h_NtWriteFile(CONTEXT *c)
{
    WCHAR path[512];
    evb b;
    char buf[8192];
    HANDLE h = (HANDLE)(uintptr_t)arg(c, 1);
    int known = query_object_path(h, path, 512) || pending_lookup(h, 1, path, 512, NULL);
    ev_init(&b, buf, sizeof(buf), "file.write", "NtWriteFile", c);
    ev_hex(&b, "handle", (unsigned long long)(uintptr_t)h);
    if (known) ev_strw(&b, "path", path);
    ev_num(&b, "size", arg32(c, 7));
    ev_end(&b);
}

static void h_NtSetInformationFile(CONTEXT *c)
{
    WCHAR path[512];
    evb b;
    char buf[8192];
    HANDLE h = (HANDLE)(uintptr_t)arg(c, 1);
    ULONG cls = (ULONG)arg32(c, 5);
    int known = query_object_path(h, path, 512) || pending_lookup(h, 1, path, 512, NULL);
    const char *type = "file.setinfo";
    WCHAR newname[512];
    newname[0] = 0;
    if (cls == 10 || cls == 20 || cls == 65) {
        type = "file.rename";
        {
            unsigned char info[32];
            ULONG64 ptr = arg(c, 3);
            ULONG namelen;
            ULONG nameoff;
            if (ptr && safe_read(info, (void *)ptr, sizeof(info))) {
#ifdef _WIN64
                memcpy(&namelen, info + 16, 4);
                nameoff = 20;
#else
                memcpy(&namelen, info + 8, 4);
                nameoff = 12;
#endif
                if (namelen > 0 && namelen < 1000) {
                    if (safe_read(newname, (void *)(uintptr_t)(ptr + nameoff), namelen)) {
                        newname[namelen / 2] = 0;
                    }
                }
            }
        }
    } else if (cls == 13 || cls == 64) {
        type = "file.delete";
    }
    ev_init(&b, buf, sizeof(buf), type, "NtSetInformationFile", c);
    ev_hex(&b, "handle", (unsigned long long)(uintptr_t)h);
    if (known) ev_strw(&b, "path", path);
    if (newname[0]) ev_strw(&b, "new_path", newname);
    ev_num(&b, "class", cls);
    ev_end(&b);
}

static void h_NtCreateKey(CONTEXT *c)
{
    WCHAR path[1024];
    evb b;
    char buf[8192];
    attr_path(arg(c, 3), path, 1024);
    pending_add((HANDLE *)(uintptr_t)arg(c, 1), 2, path, 0);
    ev_init(&b, buf, sizeof(buf), "reg.create", "NtCreateKey", c);
    ev_strw(&b, "path", path);
    ev_hex(&b, "access", arg32(c, 2));
    ev_end(&b);
}

static void h_NtOpenKey(CONTEXT *c)
{
    WCHAR path[1024];
    evb b;
    char buf[8192];
    attr_path(arg(c, 3), path, 1024);
    pending_add((HANDLE *)(uintptr_t)arg(c, 1), 2, path, 0);
    ev_init(&b, buf, sizeof(buf), "reg.open", "NtOpenKey", c);
    ev_strw(&b, "path", path);
    ev_end(&b);
}

static void h_NtOpenKeyEx(CONTEXT *c)
{
    h_NtOpenKey(c);
}

static void h_NtSetValueKey(CONTEXT *c)
{
    WCHAR path[512], name[256];
    PT_US us;
    evb b;
    char buf[8192];
    HANDLE h = (HANDLE)(uintptr_t)arg(c, 1);
    int known = query_key_path(h, path, 512) || pending_lookup(h, 2, path, 512, NULL);
    name[0] = 0;
    if (safe_read(&us, (void *)(uintptr_t)arg(c, 2), sizeof(us)))
        us_to_w(name, 256, &us);
    ev_init(&b, buf, sizeof(buf), "reg.setvalue", "NtSetValueKey", c);
    ev_hex(&b, "handle", (unsigned long long)(uintptr_t)h);
    if (known) ev_strw(&b, "path", path);
    ev_strw(&b, "name", name);
    ev_num(&b, "value_type", arg32(c, 4));
    ev_num(&b, "size", arg32(c, 6));
    ev_end(&b);
}

static void h_NtDeleteKey(CONTEXT *c)
{
    WCHAR path[512];
    evb b;
    char buf[8192];
    HANDLE h = (HANDLE)(uintptr_t)arg(c, 1);
    int known = pending_lookup(h, 2, path, 512, NULL);
    ev_init(&b, buf, sizeof(buf), "reg.delete", "NtDeleteKey", c);
    ev_hex(&b, "handle", (unsigned long long)(uintptr_t)h);
    if (known) ev_strw(&b, "path", path);
    ev_end(&b);
}

static void h_NtDeleteValueKey(CONTEXT *c)
{
    WCHAR path[512], name[256];
    PT_US us;
    evb b;
    char buf[8192];
    HANDLE h = (HANDLE)(uintptr_t)arg(c, 1);
    int known = query_key_path(h, path, 512) || pending_lookup(h, 2, path, 512, NULL);
    name[0] = 0;
    if (safe_read(&us, (void *)(uintptr_t)arg(c, 2), sizeof(us)))
        us_to_w(name, 256, &us);
    ev_init(&b, buf, sizeof(buf), "reg.delete", "NtDeleteValueKey", c);
    ev_hex(&b, "handle", (unsigned long long)(uintptr_t)h);
    if (known) ev_strw(&b, "path", path);
    ev_strw(&b, "name", name);
    ev_end(&b);
}

static void h_NtAllocateVirtualMemory(CONTEXT *c)
{
    evb b;
    char buf[8192];
    HANDLE hp = (HANDLE)(uintptr_t)arg(c, 1);
    ULONG64 base = 0, size = 0;
    DWORD target;
    safe_read(&base, (void *)(uintptr_t)arg(c, 2), sizeof(base));
    safe_read(&size, (void *)(uintptr_t)arg(c, 4), sizeof(size));
    target = handle_pid(hp);
    ev_init(&b, buf, sizeof(buf), "mem.alloc", "NtAllocateVirtualMemory", c);
    ev_num(&b, "target_pid", target);
    ev_hex(&b, "base", base);
    ev_num(&b, "size", size);
    ev_hex(&b, "protect", arg32(c, 6));
    ev_hex(&b, "alloc_type", arg32(c, 5));
    ev_end(&b);
}

static void h_NtProtectVirtualMemory(CONTEXT *c)
{
    evb b;
    char buf[8192];
    HANDLE hp = (HANDLE)(uintptr_t)arg(c, 1);
    ULONG64 base = 0, size = 0;
    DWORD target;
    safe_read(&base, (void *)(uintptr_t)arg(c, 2), sizeof(base));
    safe_read(&size, (void *)(uintptr_t)arg(c, 3), sizeof(size));
    target = handle_pid(hp);
    ev_init(&b, buf, sizeof(buf), "mem.protect", "NtProtectVirtualMemory", c);
    ev_num(&b, "target_pid", target);
    ev_hex(&b, "base", base);
    ev_num(&b, "size", size);
    ev_hex(&b, "protect", arg32(c, 4));
    ev_end(&b);
}

static void h_NtWriteVirtualMemory(CONTEXT *c)
{
    evb b;
    char buf[8192];
    HANDLE hp = (HANDLE)(uintptr_t)arg(c, 1);
    DWORD target = handle_pid(hp);
    ev_init(&b, buf, sizeof(buf), "mem.write", "NtWriteVirtualMemory", c);
    ev_num(&b, "target_pid", target);
    ev_hex(&b, "base", arg(c, 2));
    ev_num(&b, "size", arg(c, 4));
    ev_end(&b);
}

static void h_NtMapViewOfSection(CONTEXT *c)
{
    evb b;
    char buf[8192];
    HANDLE hp = (HANDLE)(uintptr_t)arg(c, 2);
    ULONG64 base = 0;
    DWORD target;
    safe_read(&base, (void *)(uintptr_t)arg(c, 3), sizeof(base));
    target = handle_pid(hp);
    ev_init(&b, buf, sizeof(buf), "mem.map", "NtMapViewOfSection", c);
    ev_num(&b, "target_pid", target);
    ev_hex(&b, "base", base);
    ev_hex(&b, "protect", arg32(c, 10));
    ev_end(&b);
}

static void h_NtCreateThreadEx(CONTEXT *c)
{
    evb b;
    char buf[8192];
    HANDLE hp = (HANDLE)(uintptr_t)arg(c, 4);
    DWORD target = handle_pid(hp);
    ev_init(&b, buf, sizeof(buf), "thread.create", "NtCreateThreadEx", c);
    ev_num(&b, "target_pid", target);
    ev_hex(&b, "start", arg(c, 5));
    ev_end(&b);
}

static void h_NtCreateThread(CONTEXT *c)
{
    evb b;
    char buf[8192];
    HANDLE hp = (HANDLE)(uintptr_t)arg(c, 4);
    ev_init(&b, buf, sizeof(buf), "thread.create", "NtCreateThread", c);
    ev_num(&b, "target_pid", handle_pid(hp));
    ev_num(&b, "suspended", arg32(c, 8));
    ev_end(&b);
}

static void h_NtUnmapViewOfSection(CONTEXT *c)
{
    evb b;
    char buf[8192];
    HANDLE hp = (HANDLE)(uintptr_t)arg(c, 1);
    ev_init(&b, buf, sizeof(buf), "mem.unmap", "NtUnmapViewOfSection", c);
    ev_num(&b, "target_pid", handle_pid(hp));
    ev_hex(&b, "base", arg(c, 2));
    ev_end(&b);
}

static void h_NtQueueApcThread(CONTEXT *c)
{
    evb b;
    char buf[8192];
    ev_init(&b, buf, sizeof(buf), "thread.apc", "NtQueueApcThread", c);
    ev_hex(&b, "thread", arg(c, 1));
    ev_hex(&b, "routine", arg(c, 2));
    ev_end(&b);
}

static void h_NtOpenProcess(CONTEXT *c)
{
    ULONG64 cid[2] = { 0, 0 };
    evb b;
    char buf[8192];
    HANDLE *out = (HANDLE *)(uintptr_t)arg(c, 1);
    safe_read(cid, (void *)(uintptr_t)arg(c, 4), sizeof(cid));
    pending_add(out, 3, L"", (DWORD)cid[0]);
    ev_init(&b, buf, sizeof(buf), "process.open", "NtOpenProcess", c);
    ev_num(&b, "target_pid", (unsigned long long)cid[0]);
    ev_hex(&b, "access", arg32(c, 2));
    ev_end(&b);
}

static void h_NtCreateUserProcess(CONTEXT *c)
{
    evb b;
    char buf[8192];
    unsigned char params[0x80];
    WCHAR image[1024] = { 0 }, cmdline[1024] = { 0 };
    ULONG64 pptr = arg(c, 9);
    if (pptr && safe_read(params, (void *)(uintptr_t)pptr, sizeof(params))) {
        PT_US us;
        size_t off;
#ifdef _WIN64
        off = 0x60;
#else
        off = 0x38;
#endif
        memcpy(&us, params + off, sizeof(us));
        us_to_w(image, 1024, &us);
        memcpy(&us, params + off + 0x10, sizeof(us));
        us_to_w(cmdline, 1024, &us);
    }
    ev_init(&b, buf, sizeof(buf), "process.create", "NtCreateUserProcess", c);
    ev_strw(&b, "image", image);
    ev_strw(&b, "cmdline", cmdline);
    ev_end(&b);
}

static void h_NtTerminateProcess(CONTEXT *c)
{
    evb b;
    char buf[8192];
    HANDLE hp = (HANDLE)(uintptr_t)arg(c, 1);
    ev_init(&b, buf, sizeof(buf), "process.terminate", "NtTerminateProcess", c);
    ev_num(&b, "target_pid", handle_pid(hp));
    ev_num(&b, "exit_code", arg32(c, 2));
    ev_end(&b);
}

static void h_NtQueryInformationProcess(CONTEXT *c)
{
    evb b;
    char buf[8192];
    ev_init(&b, buf, sizeof(buf), "proc.query", "NtQueryInformationProcess", c);
    ev_num(&b, "class", arg32(c, 2));
    ev_end(&b);
}

static void h_NtSetInformationThread(CONTEXT *c)
{
    evb b;
    char buf[8192];
    ev_init(&b, buf, sizeof(buf), "thread.setinfo", "NtSetInformationThread", c);
    ev_num(&b, "class", arg32(c, 2));
    ev_end(&b);
}

static void h_NtDelayExecution(CONTEXT *c)
{
    long long v = 0;
    evb b;
    char buf[8192];
    safe_read(&v, (void *)(uintptr_t)arg(c, 2), sizeof(v));
    ev_init(&b, buf, sizeof(buf), "sleep", "NtDelayExecution", c);
    if (v < 0) ev_num(&b, "ms", (unsigned long long)(-v) / 10000ULL);
    else ev_num(&b, "ms", 0);
    ev_end(&b);
}

static void h_NtLoadDriver(CONTEXT *c)
{
    WCHAR path[512];
    PT_US us;
    evb b;
    char buf[8192];
    path[0] = 0;
    if (safe_read(&us, (void *)(uintptr_t)arg(c, 1), sizeof(us)))
        us_to_w(path, 512, &us);
    ev_init(&b, buf, sizeof(buf), "driver.load", "NtLoadDriver", c);
    ev_strw(&b, "path", path);
    ev_end(&b);
}

static void h_connect(CONTEXT *c)
{
    unsigned char sa[32];
    evb b;
    char buf[8192];
    int family = 0, port = 0;
    char addr[64] = "";
    ULONG64 p = arg(c, 2);
    if (p && safe_read(sa, (void *)(uintptr_t)p, sizeof(sa))) {
        family = sa[0];
        if (family == 2) {
            port = (sa[2] << 8) | sa[3];
            snprintf(addr, sizeof(addr), "%u.%u.%u.%u", sa[4], sa[5], sa[6], sa[7]);
        } else if (family == 23) {
            unsigned char *a = sa + 8;
            port = (sa[2] << 8) | sa[3];
            snprintf(addr, sizeof(addr), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                     "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                     a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],
                     a[8],a[9],a[10],a[11],a[12],a[13],a[14],a[15]);
        }
    }
    ev_init(&b, buf, sizeof(buf), "net.connect", "connect", c);
    ev_stra(&b, "address", addr);
    ev_num(&b, "port", (unsigned long long)port);
    ev_num(&b, "family", (unsigned long long)family);
    ev_end(&b);
}

static void h_getaddrinfo(CONTEXT *c)
{
    char name[256] = "";
    evb b;
    char buf[8192];
    safe_read(name, (void *)(uintptr_t)arg(c, 1), sizeof(name) - 1);
    name[sizeof(name) - 1] = 0;
    ev_init(&b, buf, sizeof(buf), "net.dns", "getaddrinfo", c);
    ev_stra(&b, "host", name);
    ev_end(&b);
}

/* ------------------------------------------------------------------ */
/* hook installation / VEH                                              */
/* ------------------------------------------------------------------ */
static LONG CALLBACK pt_veh(EXCEPTION_POINTERS *ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    void *addr = ep->ExceptionRecord->ExceptionAddress;

    if (code == EXCEPTION_BREAKPOINT) {
        int i;
        hook_t *h = NULL;
        for (i = 0; i < g_hook_count; i++) {
            if (g_hooks[i].addr == addr) { h = &g_hooks[i]; break; }
        }
        if (!h) return EXCEPTION_CONTINUE_SEARCH;
        *(BYTE *)addr = h->orig;
        ep->ContextRecord->EFlags |= 0x100;
        if (!t_guard) h->fn(ep->ContextRecord);
        /* must be recorded after the handler: the handler may itself call
         * hooked APIs and consume the TLS slot for its own single-step */
        t_step_addr = addr;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code == EXCEPTION_SINGLE_STEP && t_step_addr) {
        void *a = t_step_addr;
        t_step_addr = NULL;
        *(BYTE *)a = 0xCC;
        ep->ContextRecord->EFlags &= ~0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void install(const char *dll, const char *name, hook_fn fn)
{
    HMODULE m = GetModuleHandleA(dll);
    void *addr;
    DWORD old;
    int saved;
    if (!m || g_hook_count >= MAX_HOOKS || g_hook_count >= g_hook_limit) return;
    addr = (void *)GetProcAddress(m, name);
    if (!addr) return;
    /* keep the page writable: the VEH must never call VirtualProtect(),
     * because that itself may hit a hook. */
    saved = t_guard;
    t_guard = 1;
    if (!VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &old)) { t_guard = saved; return; }
    g_hooks[g_hook_count].dll = dll;
    g_hooks[g_hook_count].name = name;
    g_hooks[g_hook_count].addr = addr;
    g_hooks[g_hook_count].orig = *(BYTE *)addr;
    g_hooks[g_hook_count].fn = fn;
    g_hook_count++;
    *(BYTE *)addr = 0xCC;
    t_guard = saved;
}

static void install_all(void)
{
    install("ntdll.dll", "NtCreateFile", h_NtCreateFile);
    install("ntdll.dll", "NtOpenFile", h_NtOpenFile);
    install("ntdll.dll", "NtDeleteFile", h_NtDeleteFile);
    install("ntdll.dll", "NtWriteFile", h_NtWriteFile);
    install("ntdll.dll", "NtSetInformationFile", h_NtSetInformationFile);
    install("ntdll.dll", "NtCreateKey", h_NtCreateKey);
    install("ntdll.dll", "NtOpenKey", h_NtOpenKey);
    install("ntdll.dll", "NtOpenKeyEx", h_NtOpenKeyEx);
    install("ntdll.dll", "NtSetValueKey", h_NtSetValueKey);
    install("ntdll.dll", "NtDeleteKey", h_NtDeleteKey);
    install("ntdll.dll", "NtDeleteValueKey", h_NtDeleteValueKey);
    install("ntdll.dll", "NtAllocateVirtualMemory", h_NtAllocateVirtualMemory);
    install("ntdll.dll", "NtProtectVirtualMemory", h_NtProtectVirtualMemory);
    install("ntdll.dll", "NtWriteVirtualMemory", h_NtWriteVirtualMemory);
    install("ntdll.dll", "NtMapViewOfSection", h_NtMapViewOfSection);
    install("ntdll.dll", "NtCreateThread", h_NtCreateThread);
    install("ntdll.dll", "NtCreateThreadEx", h_NtCreateThreadEx);
    install("ntdll.dll", "NtUnmapViewOfSection", h_NtUnmapViewOfSection);
    install("ntdll.dll", "NtQueueApcThread", h_NtQueueApcThread);
    install("ntdll.dll", "NtOpenProcess", h_NtOpenProcess);
    install("ntdll.dll", "NtCreateUserProcess", h_NtCreateUserProcess);
    install("ntdll.dll", "NtTerminateProcess", h_NtTerminateProcess);
    install("ntdll.dll", "NtQueryInformationProcess", h_NtQueryInformationProcess);
    install("ntdll.dll", "NtSetInformationThread", h_NtSetInformationThread);
    install("ntdll.dll", "NtDelayExecution", h_NtDelayExecution);
    install("ntdll.dll", "NtLoadDriver", h_NtLoadDriver);
    install("ws2_32.dll", "connect", h_connect);
    install("ws2_32.dll", "WSAConnect", h_connect);
    install("ws2_32.dll", "getaddrinfo", h_getaddrinfo);
}

/* ------------------------------------------------------------------ */
/* init                                                                 */
/* ------------------------------------------------------------------ */
static DWORD WINAPI pt_init(LPVOID unused)
{
    WCHAR logpath[1024];
    WCHAR evt[256];
    PT_LDR_ENTRY *m0;
    evb b;
    char buf[2048];

    (void)unused;
    logpath[0] = 0;
    GetEnvironmentVariableW(L"PETRACER_EVENT_LOG", logpath, 1024);
    if (!logpath[0]) return 0;
    Sleep(50);
    InitializeCriticalSection(&g_lock);
    g_lock_ready = 1;
    g_log = CreateFileW(logpath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_log == INVALID_HANDLE_VALUE) return 0;

    {
        WCHAR lim[32];
        if (GetEnvironmentVariableW(L"PETRACER_HOOK_LIMIT", lim, 32))
            g_hook_limit = _wtoi(lim);
    }
    {
        WCHAR tr[8];
        if (GetEnvironmentVariableW(L"PETRACER_TRACE_IMPORTS", tr, 8) && tr[0] == L'1')
            g_trace_imports = 1;
    }
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        g_capture = (pRtlCaptureStackBackTrace)GetProcAddress(ntdll, "RtlCaptureStackBackTrace");
        g_NtQueryObject = (LONG (WINAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG))
            GetProcAddress(ntdll, "NtQueryObject");
        g_NtQueryKey = (LONG (WINAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG))
            GetProcAddress(ntdll, "NtQueryKey");
    }
    m0 = first_module();
    if (m0) {
        g_main_base = m0->DllBase;
        g_main_size = m0->SizeOfImage;
        us_to_w(g_main_name, 260, &m0->BaseDllName);
    }

    AddVectoredExceptionHandler(1, pt_veh);
    LoadLibraryW(L"ws2_32.dll");
#ifndef PT_NO_HOOKS
    install_all();
#endif
    if (g_trace_imports) {
        int saved = t_guard;
        t_guard = 1;
        install_imports();
        t_guard = saved;
    }

    sb_init(&b, buf, sizeof(buf));
    sb_printf(&b, "{\"seq\":%ld,\"ts\":%llu,\"pid\":%lu,\"type\":\"agent.ready\","
              "\"hooks\":%d,\"imports\":%d,\"image\":",
              (long)InterlockedIncrement(&g_seq), now_ms(),
              (unsigned long)GetCurrentProcessId(), g_hook_count, g_import_count);
    sb_json_wstr(&b, g_main_name);
    sb_printf(&b, "}");
    sb_raw(&b, "\n", 1);
    if (b.ok) write_line(b.p, b.n);

    evt[0] = 0;
    if (GetEnvironmentVariableW(L"PETRACER_READY_EVENT", evt, 256) && evt[0]) {
        HANDLE h = OpenEventW(EVENT_MODIFY_STATE, FALSE, evt);
        if (h) { SetEvent(h); CloseHandle(h); }
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = h;
        DisableThreadLibraryCalls(h);
        CreateThread(NULL, 0, pt_init, NULL, 0, NULL);
    }
    return TRUE;
}
