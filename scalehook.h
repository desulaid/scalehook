/*	Copyright 2018 (c) RakLabs

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
//	Functions:
//		scalehook_unprotect(void *src, size_t size) - Getting access.
//
//		scalehook_create() - Create a hook (returns scalehook structure or nothing).
//		scalehook_destroy() - Destroy a hook. It very important! If you don't want memory leak (no return anything).
//		scalehook_create_fast() - Create a hook (with settings by default) (returns scalehook structure or nothing).
//		scalehook_fast_hook() - Fast hook (returns true/false).
//
//		scalehook_get_original_address() - Get hook original address
//		scalehook_jmp_get_relative_address() - Get relative address
//		scalehook_jmp_get_opcode() - Get hook opcodes
//		scalehook_jmp_get_src() - Get source.
//		scalehook_jmp_get_dst() - Get dest.
//		scalehook_is_installed() - Get installing state
//		scalehook_is_unprotected() - Get unprotecting state
//		scalehook_jmp_get_size() - Get size
//
//	Structures:
//		scalehook_t - scalehook structure
//		scalehook_jmp_t - scalehook jmp structure
//
//	Definited types:
//		opcode_t (unsigned char).
//		bytes_t (unsigned char *).
//  	address_t (unsigned long/long).
//
//	Opcodes:
//		Definited opcodes: jmp & call
//		Any opcodes
//
//	Supports:
//		Windows/Linux (x32/x64) (other OS didn't tested).
*/
#ifndef scalehook_h_
#define scalehook_h_

#if !defined(scalehook_windows) && !defined(scalehook_unix)
	#if defined(__WIN32__) || defined(__WIN32) || defined(WIN32) || defined(__WIN64__) || defined(__WIN64) || defined(WIN64)
		#define scalehook_windows
	#elif defined(__linux__) || defined(__linux) || defined(__LINUX__) || defined(FREEBSD) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
		#define scalehook_unix
	#endif
#endif

#if !defined(scalehook_windows) && !defined(scalehook_unix)
	#error scalehook library building error: Unknown OS
#endif

#if !defined(scalehook_x86) && !defined(scalehook_x86_x64)
	#if defined(__i386__) || defined(_X86_) || defined(_M_IX86)
		#define scalehook_x86
	#elif defined(__AMD64__) || defined(__x86_64__) || defined(_M_AMD64)
		#define scalehook_x86_x64
	#endif
#endif

#if !defined(scalehook_x86) && !defined(scalehook_x86_x64)
	#error scalehook library building error: Unsupported architecture.
#endif

#if !defined(scalehook_jmp_size)
	#if defined(scalehook_x86_x64)
		#define scalehook_jmp_size 5
	#else
		#define scalehook_jmp_size 5
	#endif
#endif

#if !defined(scalehook_cplusplus)
	#if defined(__cplusplus)
		#define scalehook_cplusplus true
	#else
		#define scalehook_cplusplus false
	#endif
#endif

#if scalehook_cplusplus
	#define scalehook_extern_c extern "C"
#else
	#define scalehook_extern_c
#endif

#if !defined(scalehook_call)
	#if defined(scalehook_windows)
		#define scalehook_call __stdcall
	#else
		#define scalehook_call
	#endif
#endif

#if !defined(scalehook_export)
	#define scalehook_export scalehook_extern_c
#endif

#if !defined(_INC_STDLIB)
	#include <stdlib.h>
#endif

#if !defined(_INC_STRING)
	#include <string.h>
#endif

#if defined(scalehook_windows)
#include <windows.h>
#else
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stddef.h>
#endif

// -------------------------------------------------

#define scalehook_opcode_jmp	0xE9
#define scalehook_opcode_call 	0xE8

// -------------------------------------------------

typedef unsigned char *bytes_t;
typedef unsigned char opcode_t;
#if defined(scalehook_x86_x64)
typedef unsigned long long address_t;
#else
typedef unsigned long address_t;
#endif

// -------------------------------------------------

typedef struct
{
	void *src;
	void *dst;
	opcode_t opcode;
	size_t size;
	void *original_bytes;
	bytes_t new_bytes;
	address_t relative_address;
} scalehook_jmp_t;

// -------------------------------------------------

typedef struct
{
	scalehook_jmp_t *scalehook_jmp;
	address_t original_address;
	int installed;
	int unprotected;
} scalehook_t;

// -------------------------------------------------

scalehook_export int scalehook_call scalehook_unprotect(void *src, size_t size);

scalehook_export int scalehook_call scalehook_execute_bytes(bytes_t bytes, void *src, size_t size);
scalehook_export scalehook_jmp_t *scalehook_call scalehook_create_jmp(void *src, void *dst, size_t size, opcode_t opcode);
scalehook_export int scalehook_call scalehook_execute_jmp(scalehook_jmp_t *scalehook_jmp);

scalehook_export scalehook_t *scalehook_call scalehook_create(void *src, void *dst, size_t size, opcode_t opcode);
scalehook_export scalehook_t *scalehook_call scalehook_create_fast(void *src, void *dst);
scalehook_export int scalehook_call scalehook_fast_hook(void *src, void *dst);
scalehook_export int scalehook_call scalehook_destroy(scalehook_t *scalehook);

scalehook_export int scalehook_call scalehook_install(scalehook_t *scalehook);
scalehook_export int scalehook_call scalehook_uninstall(scalehook_t *scalehook);

scalehook_export address_t scalehook_call scalehook_get_original_address(scalehook_t *scalehook);
scalehook_export int scalehook_call scalehook_is_installed(scalehook_t *scalehook);
scalehook_export int scalehook_call scalehook_is_unprotected(scalehook_t *scalehook);

scalehook_export void *scalehook_call scalehook_jmp_get_src(scalehook_jmp_t *scalehook_jmp);
scalehook_export void *scalehook_call scalehook_jmp_get_dst(scalehook_jmp_t *scalehook_jmp);
scalehook_export opcode_t scalehook_call scalehook_jmp_get_opcode(scalehook_jmp_t *scalehook_jmp);
scalehook_export size_t scalehook_call scalehook_jmp_get_size(scalehook_jmp_t *scalehook_jmp);
scalehook_export void *scalehook_call scalehook_jmp_get_original_bytes(scalehook_jmp_t *scalehook_jmp);
scalehook_export bytes_t scalehook_call scalehook_jmp_get_new_bytes(scalehook_jmp_t *scalehook_jmp);
scalehook_export address_t scalehook_call scalehook_jmp_get_relative_address(scalehook_jmp_t *scalehook_jmp);

// -------------------------------------------------

scalehook_export int scalehook_call scalehook_unprotect(void *src, size_t size)
{
#if defined(scalehook_windows)
	DWORD oldprotection;
	if (!VirtualProtect(src, size, PAGE_EXECUTE_READWRITE, &oldprotection))
	{
		return 0;
	}
#else
	int pagesize = sysconf(_SC_PAGE_SIZE);
	src = (void*)((address_t)src & ~(pagesize - 1));
	if (mprotect(src, size, PROT_READ | PROT_EXEC | PROT_WRITE) != 0)
	{
		return 0;
	}
#endif
	return 1;
}

scalehook_export int scalehook_call scalehook_execute_bytes(bytes_t bytes, void *src, size_t size)
{
	if(!src || !bytes || !size)
	{
		return 0;
	}
	
	memcpy(src, (void*)bytes, size);
	return 1;
}

scalehook_export scalehook_jmp_t *scalehook_call scalehook_create_jmp(void *src, void *dst, size_t size, opcode_t opcode)
{
	if (!src || !dst || !size || !opcode)
	{
		return NULL;
	}

	scalehook_jmp_t *scalehook_jmp = (scalehook_jmp_t*)malloc(sizeof(scalehook_jmp_t));
	if (!scalehook_jmp)
	{
		return NULL;
	}

	scalehook_jmp->src = src;
	scalehook_jmp->dst = dst;
	scalehook_jmp->size = size;
	scalehook_jmp->opcode = opcode;

	return scalehook_jmp;
}

scalehook_export int scalehook_call scalehook_execute_jmp(scalehook_jmp_t *scalehook_jmp)
{
	if (!scalehook_jmp)
	{
		return 0;
	}

	scalehook_jmp->original_bytes = malloc(scalehook_jmp->size);
	if (!scalehook_jmp->original_bytes)
	{
		return 0;
	}
	memcpy(scalehook_jmp->original_bytes, scalehook_jmp->src, scalehook_jmp->size);

	scalehook_jmp->new_bytes = (bytes_t)malloc(scalehook_jmp->size);
	if (!scalehook_jmp->new_bytes)
	{
		free(scalehook_jmp->original_bytes);
		return 0;
	}

	scalehook_jmp->new_bytes[0] = scalehook_jmp->opcode;
	scalehook_jmp->relative_address = (address_t)scalehook_jmp->dst - ((address_t)scalehook_jmp->src + 5);
	*(address_t*)(scalehook_jmp->new_bytes + 1) = scalehook_jmp->relative_address;

	return scalehook_execute_bytes(scalehook_jmp->new_bytes, scalehook_jmp->src, scalehook_jmp->size);
}

scalehook_export scalehook_t *scalehook_call scalehook_create(void *src, void *dst, size_t size, opcode_t opcode)
{
	if (!src || !dst || !size || !opcode)
	{
		return NULL;
	}

	scalehook_t *scalehook = (scalehook_t*)malloc(sizeof(scalehook_t));
	if (!scalehook)
	{
		return NULL;
	}

	scalehook->installed = 0;
	scalehook->unprotected = 0;

	scalehook->scalehook_jmp = scalehook_create_jmp(src, dst, size, opcode);
	if (!scalehook->scalehook_jmp)
	{
		free(scalehook);
		return NULL;
	}

	if (!scalehook_unprotect(scalehook->scalehook_jmp->src, scalehook->scalehook_jmp->size))
	{
		free(scalehook->scalehook_jmp);
		free(scalehook);
		return NULL;
	}
	scalehook->unprotected = 1;

	if (scalehook->scalehook_jmp->opcode == scalehook_opcode_call)
	{
		scalehook->original_address = ((address_t)src + 1) + ((address_t)src + 5);
	}
	else
	{
		scalehook->original_address = (address_t)src;
	}

	if (!scalehook_execute_jmp(scalehook->scalehook_jmp))
	{
		free(scalehook->scalehook_jmp);
		free(scalehook);
		return NULL;
	}

	scalehook->installed = 1;
	return scalehook;
}

scalehook_export scalehook_t *scalehook_call scalehook_create_fast(void *src, void *dst)
{
	return scalehook_create(src, dst, 5, scalehook_opcode_jmp);
}

scalehook_export int scalehook_call scalehook_fast_hook(void *src, void *dst)
{
	scalehook_t *scalehook = scalehook_create_fast(src, dst);
	if (!scalehook)
	{
		return 0;
	}

	scalehook_destroy(scalehook);
	return 1;
}

scalehook_export int scalehook_call scalehook_destroy(scalehook_t *scalehook)
{
	if (!scalehook)
	{
		return 0;
	}

	free(scalehook->scalehook_jmp->original_bytes);
	free(scalehook->scalehook_jmp->new_bytes);
	free(scalehook->scalehook_jmp);
	free(scalehook);
	return 1;
}

scalehook_export int scalehook_call scalehook_install(scalehook_t *scalehook)
{
	if (!scalehook)
	{
		return 0;
	}

	if (scalehook->installed)
	{
		return 0;
	}

	scalehook_execute_bytes(scalehook->scalehook_jmp->new_bytes, scalehook->scalehook_jmp->src, scalehook->scalehook_jmp->size);
	scalehook->installed = 1;
	return 1;
}

scalehook_export int scalehook_call scalehook_uninstall(scalehook_t *scalehook)
{
	if (!scalehook)
	{
		return 0;
	}

	if (scalehook->installed == 0)
	{
		return 0;
	}

	scalehook_execute_bytes((bytes_t)scalehook->scalehook_jmp->original_bytes, scalehook->scalehook_jmp->src, scalehook->scalehook_jmp->size);
	scalehook->installed = 0;
	return 1;
}

scalehook_export address_t scalehook_call scalehook_get_original_address(scalehook_t *scalehook)
{
	if (!scalehook)
	{
		return 0;
	}

	return scalehook->original_address;
}

scalehook_export int scalehook_call scalehook_is_installed(scalehook_t *scalehook)
{
	if (!scalehook)
	{
		return 0;
	}

	return scalehook->installed;
}

scalehook_export int scalehook_call scalehook_is_unprotected(scalehook_t *scalehook)
{
	if (!scalehook)
	{
		return 0;
	}

	return scalehook->unprotected;
}

scalehook_export void *scalehook_call scalehook_jmp_get_src(scalehook_jmp_t *scalehook_jmp)
{
	if (!scalehook_jmp)
	{
		return NULL;
	}

	return scalehook_jmp->src;
}

scalehook_export void *scalehook_call scalehook_jmp_get_dst(scalehook_jmp_t *scalehook_jmp)
{
	if (!scalehook_jmp)
	{
		return NULL;
	}

	return scalehook_jmp->dst;
}

scalehook_export opcode_t scalehook_call scalehook_jmp_get_opcode(scalehook_jmp_t *scalehook_jmp)
{
	if (!scalehook_jmp)
	{
		return 0;
	}

	return scalehook_jmp->opcode;
}

scalehook_export size_t scalehook_call scalehook_jmp_get_size(scalehook_jmp_t *scalehook_jmp)
{
	if (!scalehook_jmp)
	{
		return 0;
	}

	return scalehook_jmp->size;
}

scalehook_export void *scalehook_call scalehook_jmp_get_original_bytes(scalehook_jmp_t *scalehook_jmp)
{
	if (!scalehook_jmp)
	{
		return NULL;
	}

	return scalehook_jmp->original_bytes;
}

scalehook_export bytes_t scalehook_call scalehook_jmp_get_new_bytes(scalehook_jmp_t *scalehook_jmp)
{
	if (!scalehook_jmp)
	{
		return NULL;
	}

	return scalehook_jmp->new_bytes;
}

scalehook_export address_t scalehook_call scalehook_jmp_get_relative_address(scalehook_jmp_t *scalehook_jmp)
{
	if (!scalehook_jmp)
	{
		return 0;
	}

	return scalehook_jmp->relative_address;
}

#endif // scalehook_h_