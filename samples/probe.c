#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <winsock2.h>

int main(void) {
    Sleep(300);
    CreateDirectoryW(L"C:\\probe", NULL);
    for (int i = 0; i < 3; i++) {
        WCHAR p[64]; wsprintfW(p, L"C:\\probe\\f%d.txt", i);
        HANDLE h = CreateFileW(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(h, "data", 4, &w, NULL); CloseHandle(h); }
    }
    DeleteFileW(L"C:\\probe\\f2.txt");
    HKEY k;
    if (!RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                         0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL)) {
        RegSetValueExW(k, L"Probe", 0, REG_SZ, (const BYTE *)L"C:\\probe.exe", 22);
        RegCloseKey(k);
    }
    void *p = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (p) {
        memcpy(p, "\x90\x90\xC3", 3);
        DWORD old;
        VirtualProtect(p, 4096, PAGE_EXECUTE_READ, &old);
        VirtualFree(p, 0, MEM_RELEASE);
    }
    IsDebuggerPresent();

    STARTUPINFOW si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof si); si.cb = sizeof si;
    WCHAR cmd[] = L"C:\\windows\\system32\\cmd.exe /c echo child";
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 1500);
        HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
        if (hp) {
            void *mem = VirtualAllocEx(hp, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (mem) {
                WriteProcessMemory(hp, mem, "\xC3", 1, NULL);
                HANDLE th = CreateRemoteThread(hp, NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
                if (th) { CloseHandle(th); }
                VirtualFreeEx(hp, mem, 0, MEM_RELEASE);
            }
            CloseHandle(hp);
        }
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    WSADATA ws;
    if (!WSAStartup(MAKEWORD(2, 2), &ws)) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a; memset(&a, 0, sizeof a);
        a.sin_family = AF_INET; a.sin_port = htons(80); a.sin_addr.s_addr = inet_addr("1.2.3.4");
        connect(s, (struct sockaddr *)&a, sizeof a);
        closesocket(s);
        WSACleanup();
    }
    Sleep(1000);
    return 0;
}
