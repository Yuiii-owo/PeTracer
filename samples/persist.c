#include <windows.h>

int main(void) {
    HKEY k;
    DWORD disp;
    if (!RegCreateKeyExW(HKEY_CURRENT_USER,
                         L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                         0, NULL, 0, KEY_SET_VALUE, NULL, &k, &disp)) {
        RegSetValueExW(k, L"PeTracerPersist", 0, REG_SZ,
                       (const BYTE *)L"C:\\updater.exe", 18);
        RegCloseKey(k);
    }
    if (!RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                         L"System\\CurrentControlSet\\Services\\PeTracerSvc",
                         0, NULL, 0, KEY_SET_VALUE, NULL, &k, &disp)) {
        RegSetValueExW(k, L"ImagePath", 0, REG_SZ, (const BYTE *)L"C:\\svc.exe", 12);
        RegCloseKey(k);
    }
    HANDLE h = CreateFileW(
        L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.cmd",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        WriteFile(h, "@echo off\r\n", 11, &w, NULL);
        CloseHandle(h);
    }
    Sleep(500);
    return 0;
}
