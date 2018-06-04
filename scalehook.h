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
#pragma once
#include <iostream>
#include <string.h>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#endif

/*
//	scalehook opcodes
*/
#define scalehook_opcode_jmp			0xE8
#define scalehook_opcode_call 			0xE9

/*
//	scalehook types
*/
#define scalehook_type_method			0
#define scalehook_type_call				1

/*
//	other macroses
*/
#define scalehook_delete_safe_bytes(n)		if(n) delete[] n
#define scalehook_delete_safe(n)			if(n) delete n

/*
//	scalehook structure
*/
typedef struct
{
	// bytes
	unsigned char *original_bytes;
	unsigned char *new_bytes;
	//
	void *src;
	void *dst;
	int size;
	//
	unsigned long original_address;
	//
	unsigned char opcode;
	int type;
	//
	bool installed;
	bool unprotected;

	//
	unsigned long get_original_address()
	{
		return original_address;
	}

	unsigned char get_opcode()
	{
		return opcode;
	}

	int get_type()
	{
		return type;
	}

	bool is_installed()
	{
		return installed;
	}

	bool is_unprotected()
	{
		return unprotected;
	}

	int get_size()
	{
		return size;
	}
} scalehook_t;

// ----------------------------
// namespace :scalehook
namespace scalehook
{
	/*
	//	global scalehook functions
	*/
	bool unprotect(unsigned long src, int size);
	bool unprotect(void *src, int size);
	// cast pvoid to unsigned long
	unsigned long get_address(void *addr);
	/*
	//	cross-platform class for working with addresses too easy
	//	All samples you can find here:
	//		https://github.com/RakLabs/scalehook
	*/
	class address
	{
	private:
		unsigned long shaddr;

	public:
		address();
		address(unsigned long addr);
		address(void *addr);

		/*
		//	i think it's be easier to use = instead of .set(?)
		*/
		int operator=(unsigned long addr);
		/*
		//	of course don't forget about pvoid
		*/
		int operator=(void *addr);

		/*
		//	return address stored in shaddr var
		*/
		unsigned long get();
		/*
		//	same but in pvoid
		*/
		void *get_in_void();
	};

	/*
	//	cross-platform class for memory scanning
	//	All samples you can find here:
	//		https://github.com/RakLabs/scalehook
	*/
	class scanner
	{
	private:
		// size of image
		unsigned long size = 0;

		// image dos base
		unsigned long base = 0;

		// patern length (getting from mask length, it's so important!)
		unsigned long patternlength = 0;
		
		bool inited = false;

	public:
		/*
		//	get information about image (if we can)
		*/
		bool init(unsigned long module_addr);
		bool init(void *module_addr);

		/*
		//	find address by pattern
		*/
		address find(const char *pattern, const char *mask);
	};

	/*
	//	cross-platform class for hooking
	//	All simples you can find here:
	//		https://github.com/RakLabs/scalehook
	*/
	class hook
	{
	public:
		/*
		//	create a hook
		*/
		static scalehook_t *create(void *src, void *dst, int size = 5, int type = scalehook_type_call, unsigned char opcode = scalehook_opcode_jmp);
		static bool fast_create(void *src, void *dst);
		/*
		//	you should destroy it, after using to avoid memory leak!
		*/
		static void destroy(scalehook_t *new_scalehook);

		/*
		//	installing/uninstalling already created hook
		*/
		static bool install(scalehook_t *new_scalehook);
		static bool uninstall(scalehook_t *new_scalehook);

		/*
		// 	return stored original address
		*/
		static address get_original_address(scalehook_t *new_scalehook);
	};
}
// ----------------------------