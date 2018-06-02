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

// Function, which we want to hook
void func()
{
  cout << "func" << endl;
}

void hooked_func()
{
  cout << "hooked func" << endl;
}

int main()
{
  scalehook::hook *new_hook = new scalehook::hook((void*)func, (void*)hooked_func);
  if(!new_hook->install())
  {
    cout << "Hook failed." << endl;
  }
  func();
  new_hook->uninstall();
  // Free memory
  delete new_hook;
  return 0;
}
```
