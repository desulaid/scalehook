#include <stdio.h>
#include "scalehook.h"

scalehook_t scalehook;
typedef void(*original)(int);

void main_print(int a)
{
  printf("main_print(%i)\n", a);
}

void hook_print(int a)
{
  printf("hook_print(%i)\n", a);
  scalehook_uninstall(scalehook);
  ((original)scalehook->original_address)(a);
  scalehook_install(scalehook);
}

int main()
{
  scalehook = scalehook_create_fast((void*)main_print, (void*)hook_print);
  main_print(5);
  scalehook_destroy(scalehook);
  return 0;
}