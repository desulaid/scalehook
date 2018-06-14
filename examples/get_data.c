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
  printf("size: %i\n", scalehook_jmp_get_size(scalehook->scalehook_jmp));
}

int main()
{
  scalehook = scalehook_create((void*)main_print, (void*)hook_print, 5, scalehook_opcode_jmp);
  main_print(5);
  scalehook_destroy(scalehook);
  return 0;
}