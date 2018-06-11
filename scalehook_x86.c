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
//	Functions:
//		scalehook_unprotect(void *src, size_t size) - Getting access.
//
//		scalehook_create() - Create a hook (returns scalehook structure or nothing).
//		scalehook_destroy() - Destroy a hook. It very important! If you don't want memory leak (no return anything).
//		scalehook_create_fast() - Create a hook (with settings by default) (returns scalehook structure or nothing).
//		scalehook_fast_hook() - Fast hook (returns true/false).
//
//		scalehook_get_original_address() - Get hook original address
//		scalehook_jmp_get_opcode() - Get hook opcodes
//		scalehook_jmp_get_src() - Get source.
//		scalehook_jmp_get_dst() - Get dest.
//		scalehook_is_installed() - Get installing state
//		scalehook_is_unprotected() - Get unprotecting state
//		scalehook_jmp_get_size() - Get size
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
//
//	Opcodes:
//		Definited opcodes: jmp & call
//		Any opcodes
//
//	Supports:
//		Windows/Linux (x32/x64) (other OS didn't tested).
*/
#include "scalehook.h"
#ifdef scalehook_x86

scalehook_export scalehook_jmp_t *scalehook_call scalehook_create_jmp_x86(void *src, void *dst, size_t size, opcode_t opcode)
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

scalehook_export int scalehook_call scalehook_execute_jmp_x86(scalehook_jmp_t *scalehook_jmp)
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
	scalehook_jmp->relative_address = (unsigned long)scalehook_jmp->dst - ((unsigned long)scalehook_jmp->src + scalehook_jmp_size);
	*(unsigned long*)(scalehook_jmp->new_bytes + 1) = scalehook_jmp->relative_address;

	memcpy(scalehook_jmp->src, (void*)scalehook_jmp->new_bytes, scalehook_jmp->size);
	return 1;
}

#endif // scalehook_x86