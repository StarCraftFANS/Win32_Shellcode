#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* can't contain NULL byte */

/* messagebox shellcode*/
unsigned char shellcode[] =
"\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42"
"\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03"
"\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b"
"\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e"
"\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c"
"\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7"
"\x68\x72\x6c\x64\x01"
"\x68\x6f\x20\x57\x6f"
"\x68\x48\x65\x6c\x6c"
"\x89\xe1\xfe\x49\x0b\x31\xc0\x51\x50\xff\xd7";


unsigned char * out_C_format(unsigned char* data,int len,char* out_title,int align){
	int i;
	//printf("data contains %d bytes!\n",len);
	printf("\n%s\n\"",out_title);
	for(i=0;i<len;i++){
		printf("\\x%02x",data[i]);
		if((i+1)%align == 0 && (i+1)!=len){
			printf("\"\n\"");
		}
	}
	printf("\";\n");
	return NULL;
}



int main(int argc, char** argv){

	char buf[1024];
	int len = sizeof(shellcode);
	memset(buf,0,1024);
	sprintf(buf,"unsigned char shellcode[%d]=",len);
	out_C_format(shellcode,len,buf,16);
	
	return (0);

}