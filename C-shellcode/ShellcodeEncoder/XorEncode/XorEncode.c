#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ShellcodeHelper.h"


#define MARK		0xcc

#define XOR_KEY		0x12

#define SIZE		113


unsigned char shellcode[113] = {
    0x31, 0xD2, 0xB2, 0x30, 0x64, 0x8B, 0x12, 0x8B,
    0x52, 0x0C, 0x8B, 0x52, 0x1C, 0x8B, 0x42, 0x08,
    0x8B, 0x72, 0x20, 0x8B, 0x12, 0x80, 0x7E, 0x0C,
    0x33, 0x75, 0xF2, 0x89, 0xC7, 0x03, 0x78, 0x3C,
    0x8B, 0x57, 0x78, 0x01, 0xC2, 0x8B, 0x7A, 0x20,
    0x01, 0xC7, 0x31, 0xED, 0x8B, 0x34, 0xAF, 0x01,
    0xC6, 0x45, 0x81, 0x3E, 0x46, 0x61, 0x74, 0x61,
    0x75, 0xF2, 0x81, 0x7E, 0x08, 0x45, 0x78, 0x69,
    0x74, 0x75, 0xE9, 0x8B, 0x7A, 0x24, 0x01, 0xC7,
    0x66, 0x8B, 0x2C, 0x6F, 0x8B, 0x7A, 0x1C, 0x01,
    0xC7, 0x8B, 0x7C, 0xAF, 0xFC, 0x01, 0xC7, 0x68,
    0x72, 0x6C, 0x64, 0x01, 0x68, 0x6F, 0x20, 0x57,
    0x6F, 0x68, 0x48, 0x65, 0x6C, 0x6C, 0x89, 0xE1,
    0xFE, 0x49, 0x0B, 0x31, 0xC0, 0x51, 0x50, 0xFF,
    0xD7 
};



static void __declspec(naked) xor_encoder() {

	__asm{
		XOR     ecx,ecx
		MOV     ecx,SIZE
		LEA     esi,shellcode
	encode_loop:
		XOR     BYTE PTR [esi],XOR_KEY
		INC     esi
		loop    encode_loop
		RET		
	}
}


static void __declspec(naked) jmp_xor_decoder(){

	__asm{
			JMP     get_shellcode_addr 
	decode_start:		
			POP     esi						;esi => shellcode_start
			XOR     ecx,ecx
			sub     ecx,-SIZE				;SUB exc,-SIZE can avoid NULL bytes
	decode_loop:
			XOR		BYTE PTR [esi],XOR_KEY
			INC		esi
			LOOP	decode_loop
			JMP		shellcode_start
	
	get_shellcode_addr:
			CALL    decode_start		

	shellcode_start:
	/* 异或编码的shellcode接在后面*/
			
	}	

	//结束标示
	__asm{ __emit MARK}

}


int main(int argc, char **argv){

	unsigned char buf[1024];
	unsigned char tmp[1024];
	unsigned char *xor_decoder;

	//xor decoder code
	xor_decoder = genOpCode(jmp_xor_decoder,MARK);
	memset(buf,0,1024);
	sprintf(buf,"unsigned char xor_decoder[%d]=",strlen(xor_decoder));
	out_C_format(xor_decoder,strlen(xor_decoder),buf,16);


	if(SIZE != sizeof(shellcode) ){
		printf("change \"#define SIZE %d\"\n",sizeof(shellcode));
		exit(0);
	}
	//xor encode shellcode
	xor_encoder();
	memset(buf,0,1024);
	sprintf(buf,"unsigned char xor_shellcode[%d]=",sizeof(shellcode));
	out_C_format(shellcode,sizeof(shellcode),buf,16);

	memset(buf,0,1024);
	memset(tmp,0,1024);
	safe_strncpy(tmp,xor_decoder,strlen(xor_decoder));
	safe_strncpy(tmp+strlen(xor_decoder),shellcode,sizeof(shellcode));
	sprintf(buf,"unsigned char final_shellcode[%d]=",strlen(xor_decoder)+sizeof(shellcode));
	out_C_format(tmp,strlen(xor_decoder)+sizeof(shellcode),buf,16);

	//run shellcode
	((void(*)(void))tmp)();

	return (0);

}
