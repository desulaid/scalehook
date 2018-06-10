/*
	Copyright 2018 (c) RakLabs

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
//	Welcome to scalehook source code.
//	If you want know what's that, then read:
//		scalehook - cross-platform C/C++ hooking library.
//
//	It will be very helpful for you, if you want:
//		* know your security troubles <3
//		* hook any function c:
//		* something else?
//
//	Some features:
//		1.) Support two types.
//		2.) You can use your own opcodes (not only jmp or call).
//		3.) All! I think that's enough, ha-ha!
//
//	Functions:
//		scalehook_unprotect(void *src, size_t size) - Getting access.
//
//		scalehook_create() - Create a hook (returns scalehook structure or nothing).
//		scalehook_destroy() - Destroy a hook. It very important! If you don't want memory leak (no return anything).
//		scalehook_create_fast() - Create a hook (with settings by default) (returns scalehook structure or nothing).
//		scalehook_fast_hook() - Fast hook (returns true/false).
//
//		scalehook_get_original_address() - Get hook original address
//		scalehook_get_opcode() - Get hook opcodes
//		scalehook_get_src() - Get source.
//		scalehook_get_dst() - Get dest.
//		scalehook_is_installed() - Get installing state
//		scalehook_is_unprotected() - Get unprotecting state
//		scalehook_get_size() - Get size
//
//	Structures:
//		scalehook_t - scalehook structure
//
//	Types:
//		Method type. (no opcodes)
//		Call type. (opcodes)
//
//	Definited types:
//		opcode_t (unsigned char).
//		bytes_t (unsigned char *).
//		address_t (unsigned long).
//
//	Opcodes:
//		Definited opcodes: jmp & call
//		Any opcodes
//
//	Supports:
//		Windows/Linux (x32) (other OS didn't tested).
*/
#include "scalehook.h"
#if !defined scalehook_windows && !defined scalehook_unix
#error "Damn it! I don't know your OS ):"
#endif
#ifdef scalehook_windows
#include <windows.h>
#else
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

// -------------------------------------------------

scalehook_export int scalehook_call scalehook_unprotect(void *src, size_t size)
{
#ifdef scalehook_windows
	DWORD oldprotection;
	if(!VirtualProtect(src, size, PAGE_EXECUTE_READWRITE, &oldprotection))
	{
		return 0;
	}
#else
	int pagesize = sysconf(_SC_PAGE_SIZE);
	src = (void*)((address_t)src & ~(pagesize - 1));
	if(mprotect(src, size, PROT_READ | PROT_EXEC | PROT_WRITE) != 0)
	{
		return 0;
	}
#endif
	return 1;
}

// -------------------------------------------------

scalehook_export scalehook_t scalehook_call *scalehook_create(void *src, void *dst, size_t size, opcode_t opcode, int type)
{
	if(!src || !dst || !size || !opcode || !type)
	{
		return NULL;
	}
	
	scalehook_t *scalehook = malloc(sizeof(scalehook_t));
	if(!scalehook)
	{
		return NULL;
	}
	
	scalehook->original_bytes = malloc(size);
	if(!scalehook->original_bytes)
	{
		free(scalehook);
		return NULL;
	}
	
	// save original data
	memcpy(scalehook->original_bytes, src, size);
	scalehook->src = src;
	scalehook->dst = dst;
	scalehook->size = size;
	scalehook->opcode = opcode;
	scalehook->type = type;
	scalehook->installed = 0;
	scalehook->unprotected = 0;
	
	if(!scalehook_unprotect(src, size))
	{
		free(scalehook->original_bytes);
		free(scalehook);
		return NULL;
	}
	scalehook->unprotected = 1;
	
	if(scalehook->type == scalehook_type_method)
	{
		scalehook->original_address = (address_t)src;
		*(address_t*)scalehook->src = (address_t)scalehook->dst;
		scalehook->installed = 1;
	}
	else
	{
		scalehook->original_address = (scalehook->opcode == scalehook_opcode_call) ? ((address_t)src + 1) + ((address_t)src + 5) : (address_t)src;
		scalehook->new_bytes = malloc(size);
		scalehook->new_bytes[0] = scalehook->opcode;
		scalehook->relative_address = (address_t)dst - ((address_t)src + 5);
		*(address_t *)(scalehook->new_bytes + 1) = (address_t)dst - ((address_t)src + 5);
		memcpy(scalehook->src, scalehook->new_bytes, scalehook->size);
		scalehook->installed = 1;
	}
	
	return scalehook;
}

// -------------------------------------------------

scalehook_export scalehook_t scalehook_call *scalehook_create_fast(void *src, void *dst)
{
	return scalehook_create(src, dst, 5, scalehook_opcode_call, scalehook_type_call);
}

// -------------------------------------------------

scalehook_export void scalehook_call scalehook_destroy(scalehook_t *scalehook)
{
	if(scalehook)
	{
		free(scalehook->original_bytes);
		free(scalehook->new_bytes);
		free(scalehook);
	}
}

// -------------------------------------------------

scalehook_export int scalehook_call scalehook_fast_hook(void *src, void *dst)
{
	scalehook_t *scalehook = scalehook_create(src, dst, 5, scalehook_opcode_call, scalehook_type_call);
	if(!scalehook)
	{
		return 0;
	}
	scalehook_destroy(scalehook);
	return 1;
}

// -------------------------------------------------

scalehook_export address_t scalehook_call scalehook_get_original_address(scalehook_t *scalehook)
{
	if(!scalehook)
	{
		return 0;
	}
	
	return scalehook->original_address;
}

// -------------------------------------------------

scalehook_export address_t scalehook_call scalehook_get_relative_address(scalehook_t *scalehook)
{
	if(!scalehook)
	{
		return 0;
	}
	
	return scalehook->relative_address;
}

// -------------------------------------------------

scalehook_export size_t scalehook_call scalehook_get_size(scalehook_t *scalehook)
{
	if(!scalehook)
	{
		return 0;
	}
	
	return scalehook->size;
}

// -------------------------------------------------

scalehook_export opcode_t scalehook_call scalehook_get_opcode(scalehook_t *scalehook)
{
	if(!scalehook)
	{
		return 0;
	}
	
	return scalehook->opcode;
}

// -------------------------------------------------

scalehook_export int scalehook_call scalehook_is_installed(scalehook_t *scalehook)
{
	if(!scalehook)
	{
		return 0;
	}
	
	return scalehook->installed;
}

// -------------------------------------------------

scalehook_export int scalehook_call scalehook_is_unprotected(scalehook_t *scalehook)
{
	if(!scalehook)
	{
		return 0;
	}
	
	return scalehook->unprotected;
}

// -------------------------------------------------

scalehook_export int scalehook_call scalehook_get_type(scalehook_t *scalehook)
{
	if(!scalehook)
	{
		return 0;
	}
	
	return scalehook->type;
}

// -------------------------------------------------

scalehook_export void scalehook_call *scalehook_get_src(scalehook_t *scalehook)
{
	if(!scalehook)
	{
		return NULL;
	}
	
	return scalehook->src;
}

// -------------------------------------------------

scalehook_export void scalehook_call *scalehook_get_dst(scalehook_t *scalehook)
{
	if(!scalehook)
	{
		return NULL;
	}
	
	return scalehook->dst;
}

// -------------------------------------------------

scalehook_export unsigned char scalehook_call *scalehook_get_original_bytes(scalehook_t *scalehook)
{
	if(!scalehook)
	{
		return NULL;
	}
	
	return scalehook->original_bytes;
}

// -------------------------------------------------

scalehook_export unsigned char scalehook_call *scalehook_get_new_bytes(scalehook_t *scalehook)
{
	if(!scalehook)
	{
		return NULL;
	}
	
	return scalehook->new_bytes;
}