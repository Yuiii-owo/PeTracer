#include <winsock2.h>
#include <windows.h>

int main(void) {
    WSADATA ws;
    if (WSAStartup(MAKEWORD(2, 2), &ws) != 0) return 1;
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s != INVALID_SOCKET) {
        struct sockaddr_in a;
        ZeroMemory(&a, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons(80);
        a.sin_addr.s_addr = inet_addr("1.2.3.4");
        connect(s, (struct sockaddr *)&a, sizeof(a));
        closesocket(s);
    }
    WSACleanup();
    Sleep(300);
    return 0;
}
