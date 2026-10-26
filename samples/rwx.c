#include <windows.h>
#include <string.h>

int main(void) {
    Sleep(300);
    void *p = VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (p) {
        memset(p, 0x90, 0x1000);
        ((unsigned char *)p)[0] = 0xC3;
        DWORD old = 0;
        VirtualProtect(p, 0x1000, PAGE_EXECUTE_READ, &old);
        VirtualFree(p, 0, MEM_RELEASE);
    }
    Sleep(300);
    return 0;
}
