#include <stdio.h>


static void __declspec(naked) InvokeWinExec()
{
    __asm{
		jmp start
		find_function:
		push ebp
		mov ebp,esp
		mov eax,fs:[0x30]			;eax = fs:[0x30]ָ��PEB 
		mov eax,[eax+0x0c]    		;eax = peb->ldr
		mov eax,[eax+0x14] 			;eax ָ��peb->ldr.InMemoryOrderModuleList����ͷ
		module_loop:
		mov eax,[eax]          		;eaxָ��InMemoryOrderModuleList����һ������
		mov esi,[eax+0x28]   		;esiָ��BaseDllName->Buffer
		cmp byte ptr [esi+0x0c],'3';�ж�BaseDllName->Buffer[0x0c]==��3��
		jne module_loop
		;====================================
		;����kernel32.dll ģ��
		;====================================
		mov eax,[eax+0x10]     		;eax����kerne32ģ���ַDllBase
		;====================================
		;��λkernel32.dll PEͷ��
		;====================================
		mov edi,eax
		add edi,[edi+0x3c]    	 	;edi = IMAGE_DOS_HEADER->e_lfanew
		;====================================
		;��λkernel32.dll ������
		;====================================
		mov edi,[edi+0x78]     		;edi����kernel32.dll�������������������ַ
		add edi,eax					;edi����kernel32.dll�ĺ���������ṹ�����ַ
		mov ebx,edi    				;ebx����kernel32.dll�ĺ���������ṹ�����ַ
		;====================================
		;kernel32.dll ������������
		;====================================
		mov edi,[ebx+0x20]     		;edi����kernel32.dll�����ĺ��������������������ַ
		add edi,eax					;edi����kernel32.dll�����ĺ�����������������ַ
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
		;kernel32.dll ������������������
		;======================================
		mov edi,[ebx+0x24]
		add edi,eax
		mov ecx,[edi+ecx*2]
		and ecx,0xFFFF        		;��Ϊordinal ��USHORT����,16�ֽڴ�С
		;======================================
		;kernel32.dll����������ַ����
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
		push eax            	;��ջ������GetProcAddress������ַ
		;====================================
		;��ȡLoadLibraryA������ַ
		;====================================
		push 0x7262694c			;Libr
		push 0x64616f4c			;Load
		call find_function
		push eax            	;��ջ������LoadLibraryA������ַ
		;====================================
		; ��ȡ kernel32.dll'ģ���ַ
		;====================================
		push 0
		push '23le'            	;el32
		push 'nrek'            	;kern
		push esp              
		call eax               	;����LoadLibraryA("kernel32.dll")
		add esp,0x0c         
		;====================================
		;��ȡWinExec������ַ
		;====================================	
		push 'cex'             	;xec
		push 'EniW'            	;WinE
		push esp              	;lpProcName
		push eax              	;hModule
		call [esp+0x14]         ;����GetProcAddress(hModule,"WinExec")
		add esp,0x8           
		push 'dmc'				;'cmd'
		mov   ebx,esp
		push  1
		push  ebx
		call eax                ;����WinExec(��cmd��,1)
		add esp,0x0c                  
    }
}

int main()
{
    InvokeWinExec();
    return 0;
}