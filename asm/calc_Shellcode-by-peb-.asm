		.386
		.model flat,stdcall
		option casemap:none
;==========================================================;
;
;				ͨ����calc-Shellcode			 
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
	   mov eax,edx						;��˫������ͷָ�뱣��,��������ѭ��
	   
NextModule:
		xor ecx,ecx
		mov edx,[edx+ecx]				;ѭ���������нڵ�
		cmp eax,edx						;�жϵ�ǰ�Ľڵ�ָ���Ƿ���˫������ͷָ����ȣ���ȵĻ��ͱ�ʾû�ҵ�
		je	 GoRet						;ѭ������˫������û�ҵ�������
		
		;xor ecx,ecx							
		mov esi,[edx+20h]   			;��ȡUNICODE_STRING�ṹ��PWSTR �ַ���
		mov edi,esp						;��ջ��Kernel32���ַ���
		mov cl,8							;��ջ��Kernel32���ַ�������
		
STRCMP:		

		mov al,[esi+ecx*2-2]			;���ַ���ĩ�˿�ʼ�Ƚ�
		mov bl,[edi+ecx-1]			
		dec cl
		cmp al,bl						;�Ƚ��Ƿ����kernel32.dll��unicode��
		je STRCMP
		cmp cl,0FFh						;cl=-1ʱ��ʾƥ��ɹ�						
		jne NextModule	


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
		lea esi,[esp+0ch]				;��ջ�е� 'WinExec'
		push ecx
		mov cl,8							;WinExec���ַ������ȣ�������β��0
		repz cmpsb						;�Ƚ�ES:[ESI]��ES:[EDI]��ÿһ���ַ�
		test cl,cl
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
		lea ebx,[esp+18h]				;��ջ�е� 	'calc',0
		push 1							;SW_NORMAL	equ 1
		push ebx
		call ecx	

		
GoRet:
		add esp,20h
		popad
		ret
		
		end start