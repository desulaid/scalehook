#include <stdio.h>
#include "scalehook.h"

void main_print(int a)
{
  printf("main_print(%i)\n", a);
}

void hook_print(int a)
{
  printf("hook_print(%i)\n", a);
}

int main()
{
	scalehook_fast_hook((void*)main_print, (void*)hook_print);
	return 0;
}