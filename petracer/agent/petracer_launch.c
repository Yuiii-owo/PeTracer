/*
 * PeTracer launcher (Windows PE).
 *
 * usage: petracer_launch.exe <agent.dll> <target.exe> [args...]
 *
 * Creates the target suspended, injects the agent DLL with
 * CreateRemoteThread(LoadLibraryW), waits for the agent's ready event and
 * only then resumes the main thread.  Exits with the target's exit code.
 */
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

static void append_quoted(WCHAR *dst, size_t cap, const WCHAR *arg)
{
    size_t len = wcslen(dst);
    size_t room = cap - len - 1;
    const WCHAR *p;
    int need = 0;

    if (!room) return;
    for (p = arg; *p; p++) {
        if (*p == L' ' || *p == L'\t' || *p == L'"') { need = 1; break; }
    }
    if (!need) {
        wcsncat(dst, arg, room);
        return;
    }
    wcsncat(dst, L"\"", room);
    for (p = arg; *p; ) {
        int bs = 0;
        while (*p == L'\\') { bs++; p++; }
        if (*p == L'"') {
            int i;
            for (i = 0; i < bs * 2 + 1; i++) wcsncat(dst, L"\\", cap - wcslen(dst) - 1);
            wcsncat(dst, L"\"", cap - wcslen(dst) - 1);
            p++;
        } else {
            int i;
            for (i = 0; i < bs; i++) wcsncat(dst, L"\\", cap - wcslen(dst) - 1);
            if (*p) {
                WCHAR one[2] = { *p, 0 };
                wcsncat(dst, one, cap - wcslen(dst) - 1);
                p++;
            }
        }
    }
    wcsncat(dst, L"\"", cap - wcslen(dst) - 1);
}

static BOOL inject_dll(HANDLE hp, const WCHAR *dll)
{
    SIZE_T len = (wcslen(dll) + 1) * sizeof(WCHAR);
    void *mem;
    HMODULE k32;
    FARPROC loadlib;
    HANDLE th;
    DWORD ec = 0;
    BOOL ok = FALSE;

    mem = VirtualAllocEx(hp, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        fwprintf(stderr, L"[petracer] VirtualAllocEx failed: %lu\n", GetLastError());
        return FALSE;
    }
    if (!WriteProcessMemory(hp, mem, dll, len, NULL)) {
        fwprintf(stderr, L"[petracer] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hp, mem, 0, MEM_RELEASE);
        return FALSE;
    }
    k32 = GetModuleHandleW(L"kernel32.dll");
    loadlib = GetProcAddress(k32, "LoadLibraryW");
    th = CreateRemoteThread(hp, NULL, 0, (LPTHREAD_START_ROUTINE)loadlib, mem, 0, NULL);
    if (!th) {
        fwprintf(stderr, L"[petracer] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hp, mem, 0, MEM_RELEASE);
        return FALSE;
    }
    if (WaitForSingleObject(th, 20000) != WAIT_OBJECT_0)
        fwprintf(stderr, L"[petracer] injection thread timed out\n");
    else {
        GetExitCodeThread(th, &ec);
        ok = ec != 0;
        if (!ok) fwprintf(stderr, L"[petracer] LoadLibraryW returned 0\n");
    }
    CloseHandle(th);
    VirtualFreeEx(hp, mem, 0, MEM_RELEASE);
    return ok;
}

int wmain(int argc, WCHAR **argv)
{
    WCHAR cmd[32768];
    WCHAR evtname[256];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    HANDLE ready = NULL;
    DWORD waitrc, code = 0;
    int i;

    if (argc < 3) {
        fwprintf(stderr, L"usage: %s <agent.dll> <target.exe> [args...]\n", argv[0]);
        return 2;
    }

    cmd[0] = 0;
    for (i = 2; i < argc; i++) {
        if (i > 2) wcsncat(cmd, L" ", 32767 - wcslen(cmd));
        append_quoted(cmd, 32768, argv[i]);
    }

    evtname[0] = 0;
    GetEnvironmentVariableW(L"PETRACER_READY_EVENT", evtname, 256);
    if (evtname[0]) {
        ready = CreateEventW(NULL, TRUE, FALSE, evtname);
    }

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(argv[2], cmd, NULL, NULL, FALSE, CREATE_SUSPENDED,
                        NULL, NULL, &si, &pi)) {
        fwprintf(stderr, L"[petracer] CreateProcessW(%ls) failed: %lu\n", argv[2], GetLastError());
        return 3;
    }

    if (!inject_dll(pi.hProcess, argv[1])) {
        fwprintf(stderr, L"[petracer] PETRACER_INJECT_FAILED\n");
        /* still run the sample so WINEDEBUG-level tracing remains usable */
    } else if (ready) {
        waitrc = WaitForSingleObject(ready, 15000);
        if (waitrc != WAIT_OBJECT_0)
            fwprintf(stderr, L"[petracer] agent ready timeout\n");
    }

    if (ready) CloseHandle(ready);
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)code;
}
