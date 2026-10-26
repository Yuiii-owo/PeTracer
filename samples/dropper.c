#include <windows.h>
#include <stdio.h>

int main(void) {
    WCHAR tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    WCHAR path[MAX_PATH];
    wsprintfW(path, L"%sdropped_payload.cmd", tmp);
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        WriteFile(h, "@echo off\r\necho petracer-dropper\r\n", 34, &w, NULL);
        CloseHandle(h);
    }
    WCHAR cmd[MAX_PATH + 64];
    wsprintfW(cmd, L"cmd.exe /c \"%s\"", path);
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    Sleep(300);
    return 0;
}
