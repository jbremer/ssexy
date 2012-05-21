#include <stdio.h>
#include <windows.h>

int hoi;

void a()
{
	fprintf(stderr, "lol\n");
}

void b()
{
	hoi++;
}

void c()
{
	fprintf(stderr, "hoi: %d\n", hoi);
}

int atoi(const char *a)
{
	int ret = 0;
	while (*a) {
		ret = 10 * ret + *a++ - '0';
	}
	return ret;
}

int Main()
{
	int argc = 6; char *argv[] = {"0", "1", "2", "0", "1", "2"};
	for (int i = 0; i < argc; i++) {
		switch (atoi(argv[i])) {
		case 0: a(); break;
		case 1: b(); break;
		case 2: c(); break;
		}
	}
	return 0;
}
