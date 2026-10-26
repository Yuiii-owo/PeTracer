#include <windows.h>
#include <stdio.h>

int main(void) {
    printf("hello32 from petracer\n");
    HANDLE h = CreateFileW(L"C:\\sandbox_hello32.txt", GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        WriteFile(h, "hello32", 7, &w, NULL);
        CloseHandle(h);
    }
    Sleep(500);
    return 0;
}
