#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ShellcodeHelper.h"


#define AVALID_CHARS	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

#define ENCODE_KEY	0x58	//change it if needed

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


unsigned char* _alpha_encode(unsigned char *data,int len) {

	int i,j,m,n;
	int isFind = 0;
	unsigned char X, Y;
	unsigned char* newshellcode;

	newshellcode = malloc(2*len+1);

	for(i=0,j=0;i<len;i++,j+=2){
		
		for( m=0; m<strlen(AVALID_CHARS); m++ ) {

			X = AVALID_CHARS[m];
			
			for( n=0; n<strlen(AVALID_CHARS); n++ ) {

				Y = AVALID_CHARS[n];
				
				if( ((data[i] ^ X)&0xFF) == ((Y * ENCODE_KEY)&0xFF) ){
					isFind = 1;
					break;
				}else {
					
					isFind = 0;
				}

			}

			if(1==isFind){
				
				newshellcode[j] = X;
				newshellcode[j+1] = Y;
				//printf("\\x%02x\\x%02x\n",X,Y);
				break;
			}

		}

		if(0==isFind){
			printf("can not encode data[i]=0x%02x\n\n",i,data[i]);
			exit(0);
		}
	
		isFind = 0;

	}

	newshellcode[2*len] = '\x0';
	//printf("\n");
	return newshellcode;
}



unsigned char* alpha_encode(unsigned char *data,int len) {

	int i,j;
	int isFind = 0;
	unsigned char X, Y;
	unsigned char* newshellcode;

	newshellcode = malloc(2*len+1);

	for(i=0,j=0;i<len;i++,j+=2){
		
		for( X='0'; X<'z'; X++ ) {	//from '0' to 'z'

			if(( X>'9' && X<'A' ) || ( X>'Z' && X<'a' )) continue; //non alpha
			
			for( Y='0'; Y<'z'; Y++ ) {

				if(( Y>'9' && Y<'A' ) || ( Y>'Z' && Y<'a' )) continue;	//non alpha
					
				if( ((data[i] ^ X)&0xFF) == ((Y * ENCODE_KEY)&0xFF) ){
					
					isFind = 1;
					break;
				}else {
					
					isFind = 0;
				}

			}

			if(1==isFind){
				
				newshellcode[j] = X;
				newshellcode[j+1] = Y;
				//printf("\\x%02x\\x%02x",X,Y);
				break;
			}

		}

		if(0==isFind){
			printf("can not encode data[i]=0x%02x\n\n",i,data[i]);
			exit(0);
		}
	
		isFind = 0;

	}

	newshellcode[2*len] = '\x0';
	//printf("\n");
	return newshellcode;
}


static void __declspec(naked) alpha_decoder() {

	__asm{

		PUSH    eax				;eax must be pointer the encoded shellcode
		POP     edx				;edx = eax => shellcode
		
		;clear eax
		PUSH    'ABCD'			
		POP     eax				
		XOR     eax,'ABCD'		;eax = 0
        
		DEC     eax				;eax = 0xFFFFFFFF
		  


	}

}


void testAllAsicc( ){
	unsigned char tmp[1];
	unsigned char *ret;
	int i = 0;
	for(i=0x00;i<=0xFF;i++){
		tmp[0] = i;
		printf("tmp[0]=0x%02x   ==>  ",tmp[0]);
		ret = alpha_encode(tmp,1);
		printf("%s\n",ret);
	}
}


int main(int argc, char **argv) {
	unsigned char buf[1024];
	unsigned char tmp[1024];
	unsigned char * alpha_encode_shellcode;
	unsigned char * alpha_decoder;

	if(SIZE != sizeof(shellcode)) {
		printf("please change \"#define SIZE %d\"",sizeof(shellcode));	

	}
	// alpha encode shellcode
	alpha_encode_shellcode = alpha_encode(shellcode,sizeof(shellcode));
	printf("unsigned char alpha_encode_shellcode[%d]=\n\"%s\"\n\n",2*sizeof(shellcode),alpha_encode_shellcode);

	/*
	//combine final alpha2 shellcode
	memset(buf,0,1024);
	memset(tmp,0,1024);
	safe_strncpy(tmp,alpha2_decoder,strlen(alpha2_decoder));
	safe_strncpy(tmp+strlen(alpha2_decoder),alpha2_encode_shellcode,2*sizeof(shellcode));
	sprintf(buf,"unsigned char final_shellcode[%d]=",strlen(alpha2_decoder)+2*sizeof(shellcode));
	out_C_format(tmp,strlen(alpha2_decoder)+2*sizeof(shellcode),buf,16);
	*/

}

