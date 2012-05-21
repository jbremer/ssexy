#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

void xor(unsigned char *buf, char key, int len)
{
	while (len--) *buf++ ^= key;
}

char g_bla[256];

void set_index(int index, char key)
{
	g_bla[index] = key;
}

void print(int index)
{
	fprintf(stderr, "%d -> %d\n", index, g_bla[index]);
}

int Main()
{
	char cat_str[] = "the cat jumps over a lazy fox, ofzo";
	xor((unsigned char *) cat_str, 4, strlen(cat_str));

	set_index(32, cat_str[8]);
	print(32);

	fprintf(stderr, "cat-str: %s\n", cat_str);
	return 0;
}