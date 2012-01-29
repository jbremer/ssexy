# store test.cpp header
cat > testing.cpp <<EOL
#include <stdio.h>
#include <windows.h>
#include "jbade/jbade.h"

DWORD WINAPI MmxThread(LPVOID)
{
	static unsigned long a[4] = {0x11111111, 0x22222222, 0x33333333, 0x44444444}, b[4] = {0x55555555, 0x66666666, 0x77777777, 0x88888888};
	__asm__(
		".intel_syntax noprefix \n"
		
		"mov eax, %0 \n"
		"movapd xmm6, [eax] \n"
		
		"mov eax, %1 \n"
		"movapd xmm7, [eax] \n"
		
EOL

# store the generated assembly
python sseify.py $1 >> testing.cpp

# store test.cpp footer
cat >> testing.cpp <<EOL

		
		".att_syntax"
		:: "r" (a), "r" (b)
		: "eax"
	);
	while (1);
}

int main(int argc, char *argv[])
{
	HANDLE hThread = CreateThread(NULL, 0, MmxThread, NULL, 0, NULL);
	Sleep(100);
	SuspendThread(hThread);
	CONTEXT Ctx = {}; Ctx.ContextFlags = CONTEXT_FULL | CONTEXT_EXTENDED_REGISTERS;
	GetThreadContext(hThread, &Ctx);
	for (int i = 0; i < 8; i++) {
		unsigned long *xmm = (unsigned long *)(Ctx.ExtendedRegisters + 0xa0 + 16 * i);
		printf("xmm%d: %08x %08x %08x %08x - %d %d %d %d\r\n", i, *xmm, xmm[1], xmm[2], xmm[3], *xmm, xmm[1], xmm[2], xmm[3]);
	}
	const char *regs[] = {"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"};
	for (int i = 0; i < 8; i++) {
		unsigned long value = *(unsigned long *)(Ctx.ExtendedRegisters + 0xa0 + 16 * 6 + 4 * i);
		printf("%s: %08x %d\r\n", regs[i], value, value);
	}
}

EOL

# build test exe
g++ testing.cpp -o testing

# delete old source
rm testing.cpp

# run test exe
./testing