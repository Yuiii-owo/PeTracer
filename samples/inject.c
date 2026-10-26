#include <windows.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        Sleep(15000);
        return 0;
    }
    WCHAR self[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    WCHAR cmd[MAX_PATH + 16];
    wsprintfW(cmd, L"\"%s\" child", self);
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        return 1;
    }
    Sleep(1200);
    HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
    if (hp) {
        void *mem = VirtualAllocEx(hp, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
        if (mem) {
            WriteProcessMemory(hp, mem, "\xC3", 1, NULL);
            HANDLE th = CreateRemoteThread(hp, NULL, 0, (LPTHREAD_START_ROUTINE)mem,
                                           NULL, 0, NULL);
            if (th) {
                WaitForSingleObject(th, 2000);
                CloseHandle(th);
            }
            VirtualFreeEx(hp, mem, 0, MEM_RELEASE);
        }
        CloseHandle(hp);
    }
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
