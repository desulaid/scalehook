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
scalehook::address::address() {}
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

bool scalehook::address::isnull()
{
	return (shaddr == 0);
}

// -----------------------------------

// -----------------------------------
// class :scanner
scalehook::scanner::scanner(void *module)
{
	module_addr = module;
}
bool scalehook::scanner::init()
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
	inited = true;
	return true;
}
scalehook::address scalehook::scanner::find(const char *pattern, const char *mask)
{
	if(!inited)
	{
		init();
	}
	
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
scalehook_t *scalehook::hook::create(void *src, void *dst, int size, int type, unsigned char opcode)
{
	scalehook_t *new_scalehook = new scalehook_t();
	/*
	//	store original data
	*/
	new_scalehook->original_bytes = new unsigned char[size];
	memcpy(new_scalehook->original_bytes, src, size);

	new_scalehook->size = size;
	new_scalehook->src = src;
	new_scalehook->dst = dst;
	new_scalehook->type = type;
	new_scalehook->opcode = opcode;

	if (!unprotect(new_scalehook->src, new_scalehook->get_size()))
	{
		scalehook_delete_safe_bytes(new_scalehook->original_bytes);
		scalehook_delete_safe(new_scalehook);
		return NULL;
	}

	new_scalehook->unprotected = true;
	if (new_scalehook->get_type() == scalehook_type_method)
	{
		new_scalehook->original_address = (unsigned long)new_scalehook->src;
		*(unsigned long*)new_scalehook->src = (unsigned long)new_scalehook->dst;
		new_scalehook->installed = true;
	}
	else if (new_scalehook->get_type() == scalehook_type_call)
	{
		new_scalehook->new_bytes = new unsigned char[new_scalehook->get_size()];

		if (new_scalehook->get_opcode() == scalehook_opcode_jmp)
		{
			new_scalehook->new_bytes[0] = scalehook_opcode_jmp;
			new_scalehook->original_address = (unsigned long)src;
		}
		else
		{
			new_scalehook->new_bytes[0] = scalehook_opcode_call;
			new_scalehook->original_address = (unsigned long)src + 1 + (unsigned long)src + 1;
		}

		*(unsigned long*)(new_scalehook->new_bytes + 1) = (unsigned long)new_scalehook->dst - ((unsigned long)new_scalehook->src + 5);
		memcpy(new_scalehook->src, (void*)new_scalehook->new_bytes, new_scalehook->size);
		new_scalehook->installed = true;
	}
	else
	{
		scalehook_delete_safe_bytes(new_scalehook->original_bytes);
		scalehook_delete_safe(new_scalehook);
		return NULL;
	}

	return new_scalehook;
}
bool scalehook::hook::fast_create(void *src, void *dst)
{
	bool result = true;
	scalehook_t *new_hook = create(src, dst);
	if(!new_hook)
	{
		result = false;
	}
	destroy(new_hook);
	return result;
}
void scalehook::hook::destroy(scalehook_t *new_scalehook)
{
	scalehook_delete_safe_bytes(new_scalehook->original_bytes);
	scalehook_delete_safe_bytes(new_scalehook->new_bytes);
	scalehook_delete_safe(new_scalehook);
}
bool scalehook::hook::install(scalehook_t *new_scalehook)
{
	if (!new_scalehook)
	{
		return false;
	}

	if (new_scalehook->is_installed())
	{
		return false;
	}

	if (!new_scalehook->is_unprotected())
	{
		if(!unprotect(new_scalehook->src, new_scalehook->get_size())) return false;
		new_scalehook->unprotected = true;
	}

	memcpy(new_scalehook->src, (void*)new_scalehook->new_bytes, new_scalehook->size);
	new_scalehook->installed = true;

	return true;
}
bool scalehook::hook::uninstall(scalehook_t *new_scalehook)
{
	if (!new_scalehook)
	{
		return false;
	}

	if (!new_scalehook->is_installed())
	{
		return false;
	}

	if (!new_scalehook->is_unprotected())
	{
		if(new_scalehook->is_unprotected()) return false;
		new_scalehook->unprotected = true;
	}

	memcpy(new_scalehook->src, (void*)new_scalehook->original_bytes, new_scalehook->size);
	new_scalehook->installed = false;

	return true;
}
scalehook::address scalehook::hook::get_original_address(scalehook_t *new_scalehook)
{
	if (!new_scalehook)
	{
		return address((void*)NULL);
	}

	return address(new_scalehook->original_address);
}
// -----------------------------------
