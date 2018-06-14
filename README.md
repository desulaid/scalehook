# scalehook
Welcome! I'm glad you came here. I hope that my new library will be very useful for your project! So, this is an hooking library that works on any platform! If you are really interested in this, then we can continue! <br></br>

The main advantages of this library:
1. Works on any platform!
2. You can use it for x32 and x64 architecture!
3. Easy to install and simple for use! <br></br>

Also you can use my library not only for C, but for C++ too! You will not find it difficult to use it in any of these languages!

## Note
If you want use it for C++, you should change scalehook source file extension to .cpp! Example: scalehook.`c`=>`cpp`. I hope for you it will not be difficult!

## Contributing
If you want to help me in the develop, then write me a mail! I will write to you about what you can help me, I will be very grateful for your help!

## Issue
If you find a problem when using scalehook, please describe it [here](https://github.com/RakLabs/scalehook/issues). I will try to solve it as soon as possible!

## Examples
Of course, I'll give you examples of using this library, where without them! Now, I show you, how you can hook function, using this library.
```c
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
  scalehook = scalehook_create((void*)main_print, (void*)hook_print, 5, scalehook_opcode_jmp);
  main_print(5);
  /*
    want know result?
    Then try it yourself)!
  */
  
  /*
    but don't forget about destroy!
    I think better just destroy hook, instead of get memory leak)
  */
  scalehook_destroy(scalehook);
  return 0;
}
```
I think, it's very easy, isn't it? But i think you have a question "How can i call the original function?". But believe me, it's just as easy!
```c
#include <stdio.h>
#include "scalehook.h"

scalehook_t scalehook;

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
  scalehook = scalehook_create((void*)main_print, (void*)hook_print, 5, scalehook_opcode_jmp);
  main_print(5);
  /*
    want know result?
    Then try it yourself)!
  */
  
  /*
    but don't forget about destroy!
    I think better just destroy hook, instead of get memory leak)
  */
  scalehook_destroy(scalehook);
  return 0;
}
```

More examples you can see here (Also there you can see more simple ways of hooking). Well, on this, have a nice day!!!
