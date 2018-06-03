# scalehook
cross-platform C++ hooking library

## Include
1.) Cross-platform memory scanner<br>
2.) Cross-platform class for working with addresses<br>
3.) Cross-platform class for hooking

## Types
1.) Call type<br>
2.) Method type

## Usage
```C++
#include <iostream>
#include "scalehook.h"

using namespace std;
/* using namespace scalehook; */

scalehook_t *new_hook;

void __cdecl hooked_func_print()
{
  cout << "Hooked." << endl;
  scalehook::hook::uninstall(new_hook);
  reinterpret_cast<void(__cdecl*)()>(new_hook->get_original_address())();
  /*
  //  Required to avoid memory leak!!!!
  */
  scalehook::hook::destroy(new_hook);
}

void __cdecl func_print()
{
  cout << "Print." << endl;
}

int main()
{
  new_hook = scalehook::hook::create((void*)func_print, (void*)hooked_func_print);
  return 0;
}
```
Fast hook:
```C++
#include <iostream>
#include "scalehook.h"

using namespace std;
/* using namespace scalehook; */

void __cdecl hooked_func_print()
{
  cout << "Hooked." << endl;
}

void __cdecl func_print()
{
  cout << "Print." << endl;
}

int main()
{
  scalehook::hook::fast_create((void*)func_print, (void*)hooked_func_print);
  return 0;
}
```
