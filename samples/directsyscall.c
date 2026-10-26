#include <windows.h>
#include <stdio.h>

/* Kept in the image (never called) so static triage sees the opcode. */
__attribute__((used, noinline)) static void petracer_raw_syscall_probe(void) {
    __asm__ volatile(
        "movl $0x18, %%eax\n\t"
        "xorq %%r10, %%r10\n\t"
        "syscall\n\t"
        :
        :
        : "rax", "r10", "rcx", "r11", "memory");
}

int main(void) {
    printf("direct syscall carrier\n");
    HANDLE h = CreateFileW(L"C:\\direct.txt", GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        WriteFile(h, "x", 1, &w, NULL);
        CloseHandle(h);
    }
    Sleep(300);
    return 0;
}
