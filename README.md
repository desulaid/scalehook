# scalehook
cross-platform C/C++ hooking library. I hope this library will be very useful for your project.

## Functions
Here are all scalehook's functions.<br></br>
```scalehook_export scalehook_t scalehook_call *scalehook_create(void *src, void *dst, size_t size, opcode_t opcode, int type);``` - create a new hook<br>
```scalehook_export scalehook_t scalehook_call *scalehook_create_fast(void *src, void *dst);``` - create a new hook (but with arguments by default).<br>
```scalehook_export void scalehook_call scalehook_destroy(scalehook_t *scalehook);``` - destroy a hook. (It's very improtant, if you don't want memory leak).<br>
```scalehook_export int scalehook_call scalehook_fast_hook(void *src, void *dst);``` - just hook without returning scalehook structure.<br>
```scalehook_export int scalehook_call scalehook_install(scalehook_t *scalehook);``` - install already created hook.<br>
```scalehook_export int scalehook_call scalehook_uninstall(scalehook_t *scalehook);``` - uninstall already created hook.<br></br>

Functions for getting information about hook:<br>
```c
scalehook_export unsigned long scalehook_call scalehook_get_original_address(scalehook_t *scalehook);
scalehook_export int scalehook_call scalehook_is_installed(scalehook_t *scalehook);
scalehook_export int scalehook_call scalehook_is_unprotected(scalehook_t *scalehook);

scalehook_export void *scalehook_call scalehook_jmp_get_src(scalehook_jmp_t *scalehook_jmp);
scalehook_export void *scalehook_call scalehook_jmp_get_dst(scalehook_jmp_t *scalehook_jmp);
scalehook_export opcode_t scalehook_call scalehook_jmp_get_opcode(scalehook_jmp_t *scalehook_jmp);
scalehook_export size_t scalehook_call scalehook_jmp_get_size(scalehook_jmp_t *scalehook_jmp);
scalehook_export void *scalehook_call scalehook_jmp_get_original_bytes(scalehook_jmp_t *scalehook_jmp);
scalehook_export bytes_t scalehook_call scalehook_jmp_get_new_bytes(scalehook_jmp_t *scalehook_jmp);
scalehook_export unsigned long scalehook_call scalehook_jmp_get_relative_address(scalehook_jmp_t *scalehook_jmp);
```

## Example
```c
#include <stdio.h>
#include "scalehook.h"

scalehook_t *new_hook;
typedef void(*original)();

void kek()
{
  printf("2: Hook successfull.\n");
  printf("3: Calling original function..\n");
  scalehook_uninstall(new_hook);
  ((original)new_hook->original_address)();
  scalehook_install(new_hook);
}

void lol()
{
  printf("lol\n");
}

int main(void)
{
  new_hook = scalehook_create(lol, kek, 5, scalehook_opcode_jmp, scalehook_type_call);
  if(!new_hook)
  {
    printf("1: Hook failed.\n");
  }
  lol();
  scalehook_destroy(new_hook);
  return 0;
}
```

## Test
If you want to test scalehook, then:
1. Clone this repository
2. Enter in terminal: `make`
3. Done.
