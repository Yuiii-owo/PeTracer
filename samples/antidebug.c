#include <windows.h>

typedef LONG (WINAPI *pNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG (WINAPI *pNtSIT)(HANDLE, ULONG, PVOID, ULONG);
typedef LONG (WINAPI *pNtDelay)(BOOLEAN, PLARGE_INTEGER);

static DWORD WINAPI sleeper(void *param) {
    LARGE_INTEGER li;
    li.QuadPart = -650000000LL;
    ((pNtDelay)param)(FALSE, &li);
    return 0;
}

int main(void) {
    ULONG_PTR port = 0;
    ULONG ret = 0;
    IsDebuggerPresent();
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    pNtQIP q = (pNtQIP)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (q) q(GetCurrentProcess(), 7, &port, sizeof(port), &ret);
    pNtSIT s = (pNtSIT)GetProcAddress(ntdll, "NtSetInformationThread");
    if (s) s(GetCurrentThread(), 0x11, NULL, 0);
    pNtDelay d = (pNtDelay)GetProcAddress(ntdll, "NtDelayExecution");
    if (d) CreateThread(NULL, 0, sleeper, (void *)d, 0, NULL);
    Sleep(1000);
    return 0;
}
