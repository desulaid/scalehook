/*
	Copyright 2018 RakLabs

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/
/*
//	scalehook - cross-platform C++ hooking library.
//	include:
//		cross-platform class for working with addresses
//		cross-platform class for memory scanning
//		cross-platform class for hooking
//
//	All samples you can find here:
//		https://github.com/RakLabs/scalehook
*/
#include "scalehook.h"

// -----------------------------------
// namespace :scalehook (global functions)
bool scalehook::unprotect(unsigned long src, int size)
{
	return unprotect(reinterpret_cast<void*>(src), size);
}
bool scalehook::unprotect(void *src, int size)
{
#ifdef _WIN32
	DWORD oldprotection;
	if (!VirtualProtect(src, size, PAGE_EXECUTE_READWRITE, &oldprotection))
	{
		return false;
	}
#else
	long pagesize;
	pagesize = sysconf(_SC_PAGESIZE);
	src = (void *)((long)src & ~(pagesize - 1));
	if (mprotect(src, size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
	{
		return false;
	}
#endif
	return true;
}
unsigned long scalehook::get_address(void *addr)
{
	return reinterpret_cast<unsigned long>(addr);
}
// -----------------------------------

// -----------------------------------
// class :address
scalehook::address::address(){}
scalehook::address::address(unsigned long addr)
{
	shaddr = addr;
}
scalehook::address::address(void *addr)
{
	shaddr = reinterpret_cast<unsigned long>(addr);
}

// -----------------------------------
// operator :=
int scalehook::address::operator=(unsigned long addr)
{
	shaddr = addr;
	return shaddr;
}
int scalehook::address::operator=(void *addr)
{
	shaddr = reinterpret_cast<unsigned long>(addr);
	return shaddr;
}
// -----------------------------------

unsigned long scalehook::address::get()
{
	return shaddr;
}

void *scalehook::address::get_in_void()
{
	return reinterpret_cast<void*>(shaddr);
}

// -----------------------------------

// -----------------------------------
// class :scanner
bool scalehook::scanner::init(unsigned long module_addr)
{
	return init(reinterpret_cast<void*>(module_addr));
}
bool scalehook::scanner::init(void *module_addr)
{
#ifdef _WIN32
	MEMORY_BASIC_INFORMATION module_info;
	if (!VirtualQuery(module_addr, &module_info, sizeof(module_info)))
	{
		return false;
	}

	auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module_info.AllocationBase);
	auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<unsigned long>(dos) + dos->e_lfanew);

	if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

	base = (unsigned long)module_info.AllocationBase;
	size = (unsigned long)nt->OptionalHeader.SizeOfImage;
#else
	Dl_info module_info;
	struct stat stat_buf;

	if (!dladdr(reinterpret_cast<void*>(module_addr), &module_info)) return false;
	if (stat(module_info.dli_fname, &stat_buf) != 0) return false;

	base = (unsigned long)module_info.dli_fbase;
	size = (unsigned long)stat_buf.st_size;
#endif
	return true;
}
scalehook::address scalehook::scanner::find(const char *pattern, const char *mask)
{
	if (!base || !size)
	{
		return address();
	}
	patternlength = (unsigned long)strlen(mask);
	if (!patternlength)
	{
		return address();
	}

	for (unsigned long i = 0; i < size - patternlength; i++)
	{
		bool found = true;
		for (unsigned long j = 0; j < patternlength; j++)
		{
			found &= mask[j] == '?' || pattern[j] == *(char*)(base + j + i);
		}
		if (found) return address(base + i);
	}
	return address();
}
// -----------------------------------

// -----------------------------------
// class :hook
scalehook::hook::hook(void *src, void *dst, int type, int opcode, int len)
{
	scalehook_src = src;
	scalehook_dst = dst;
	scalehook_len = len;
	scalehook_installed = false;
	scalehook_unprotected = false;
	scalehook_opcode = opcode;
	scalehook_type = type;
}
bool scalehook::hook::unprotect()
{
	if (scalehook_unprotected)
	{
		return false;
	}

	if (scalehook::unprotect(scalehook_src, scalehook_len))
	{
		scalehook_unprotected = true;
		return true;
	}
	return false;
}
bool scalehook::hook::install()
{
	if (!scalehook_src || !scalehook_dst || !scalehook_len || scalehook_installed)
	{
		return false;
	}

	if (!scalehook_unprotected && !unprotect())
	{
		return false;
	}
	
	if(scalehook_type == scalehook_type_method)
	{
		*(unsigned long*)scalehook_src = (unsigned long)scalehook_dst;
		return true;
	}
	else if(scalehook_type == scalehook_type_call)
	{
	
		unsigned char *_new_bytes = new unsigned char[scalehook_len];

		if (scalehook_opcode == jmp_opcode)
		{
			_new_bytes[0] = jmp_opcode;
			scalehook_original_address = reinterpret_cast<unsigned long>(scalehook_src);
		}
		else
		{
			_new_bytes[0] = call_opcode;
			scalehook_original_address = ((reinterpret_cast<unsigned long>(scalehook_src) + 1) + (reinterpret_cast<unsigned long>(scalehook_src) + 5));
		}

		*reinterpret_cast<unsigned long*>(_new_bytes + 1) = reinterpret_cast<unsigned long>(scalehook_dst) - (reinterpret_cast<unsigned long>(scalehook_src) + 5);
		memcpy(scalehook_src, _new_bytes, scalehook_len);

		// free memory
		delete[] _new_bytes;
		scalehook_installed = true;
		return true;
	}
	return false;
}
bool scalehook::hook::uninstall()
{
	if (!scalehook_installed)
	{
		return false;
	}
	memset(scalehook_src, 0x90, scalehook_len);
	scalehook_installed = false;
}
scalehook::address scalehook::hook::get_original_address()
{
	return scalehook_original_address;
}
// -----------------------------------
