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
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include 
#endif

/*
//	scalehook opcodes
*/
#define jmp_opcode					0xE8
#define call_opcode 				0xE9

/*
//	scalehook types
*/
#define scalehook_type_method		0
#define scalehook_type_call			1

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

		// patern length (getting from mask length, it's so property!)
		unsigned long patternlength = 0;

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
	private:
		/*
		//	scale hook info
		*/
		address scalehook_original_address;
		void *scalehook_dst;
		void *scalehook_src;
		int scalehook_len;
		int scalehook_opcode;
		int scalehook_type;

		/*
		//	to avoid double installing
		*/
		bool scalehook_installed;

		/*
		//	to avoid double unprotecting
		*/
		bool scalehook_unprotected;

	public:
		/*
		//	set scale hook info
		*/
		hook(void *src, void *dst, int type = scalehook_type_call, int opcode = jmp_opcode, int len = 5);

		bool unprotect();
		bool install();
		bool uninstall();
		
		/*
		// 	return stored original address (src)
		*/
		address get_original_address();
	};
}
// ----------------------------