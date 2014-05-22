#include <stdio.h>


static void __declspec(naked) InvokeWinExec()
{
    __asm{
		jmp start
		find_function:
		push ebp
		mov ebp,esp
		mov eax,fs:[0x30]			;eax = fs:[0x30]指向PEB 
		mov eax,[eax+0x0c]    		;eax = peb->ldr
		mov eax,[eax+0x14] 			;eax 指向peb->ldr.InMemoryOrderModuleList链表头
		module_loop:
		mov eax,[eax]          		;eax指向InMemoryOrderModuleList的下一个链表
		mov esi,[eax+0x28]   		;esi指向BaseDllName->Buffer
		cmp byte ptr [esi+0x0c],'3';判断BaseDllName->Buffer[0x0c]==’3’
		jne module_loop
		;====================================
		;查找kernel32.dll 模块
		;====================================
		mov eax,[eax+0x10]     		;eax保存kerne32模块基址DllBase
		;====================================
		;定位kernel32.dll PE头部
		;====================================
		mov edi,eax
		add edi,[edi+0x3c]    	 	;edi = IMAGE_DOS_HEADER->e_lfanew
		;====================================
		;定位kernel32.dll 导出表
		;====================================
		mov edi,[edi+0x78]     		;edi保存kernel32.dll函数导出表的相对虚拟地址
		add edi,eax					;edi保存kernel32.dll的函数导出表结构虚拟地址
		mov ebx,edi    				;ebx保存kernel32.dll的函数导出表结构虚拟地址
		;====================================
		;kernel32.dll 函数名称数组
		;====================================
		mov edi,[ebx+0x20]     		;edi保存kernel32.dll导出的函数名词数组的相对虚拟地址
		add edi,eax					;edi保存kernel32.dll导出的函数名词数组的虚拟地址
		xor ecx,ecx           
		name_loop:
		mov esi,[edi+ecx*4]
		add esi,eax
		inc ecx
		mov edx,[esp+8]       
		cmp dword ptr [esi],edx
		jne name_loop
		mov edx,[esp+0xc]   
		cmp dword ptr [esi+4],edx
		jne name_loop
		;======================================
		;kernel32.dll 导出函数索引号数组
		;======================================
		mov edi,[ebx+0x24]
		add edi,eax
		mov ecx,[edi+ecx*2]
		and ecx,0xFFFF        		;因为ordinal 是USHORT类型,16字节大小
		;======================================
		;kernel32.dll导出函数地址数组
		;======================================
		mov edi,[ebx+0x1c]
		add edi,eax
		dec ecx
		sal ecx,2
		mov edi,[edi+ecx]
		add eax,edi
		pop ebp
		ret 8
		start:
		;====================================
		; Get GetProcAddress's address
		;====================================
		push 0x41636f72    		;rocA
		push 0x50746547    		;Getp
		call find_function
		push eax            	;在栈顶保存GetProcAddress函数地址
		;====================================
		;获取LoadLibraryA函数地址
		;====================================
		push 0x7262694c			;Libr
		push 0x64616f4c			;Load
		call find_function
		push eax            	;在栈顶保存LoadLibraryA函数地址
		;====================================
		; 获取 kernel32.dll'模块基址
		;====================================
		push 0
		push '23le'            	;el32
		push 'nrek'            	;kern
		push esp              
		call eax               	;调用LoadLibraryA("kernel32.dll")
		add esp,0x0c         
		;====================================
		;获取WinExec函数地址
		;====================================	
		push 'cex'             	;xec
		push 'EniW'            	;WinE
		push esp              	;lpProcName
		push eax              	;hModule
		call [esp+0x14]         ;调用GetProcAddress(hModule,"WinExec")
		add esp,0x8           
		push 'dmc'				;'cmd'
		mov   ebx,esp
		push  1
		push  ebx
		call eax                ;调用WinExec(“cmd”,1)
		add esp,0x0c                  
    }
}

int main()
{
    InvokeWinExec();
    return 0;
}