#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static unsigned char * out_C_format(unsigned char* data,int len,char* out_title,int align){
	int i;
	//printf("data contains %d bytes!\n",len);
	printf("\n%s\n\"",out_title);
	for(i=0;i<len;i++){
		//if(('0'<=data[i]&&'9'>=data[i])||('a'<=data[i]&&'z'>=data[i])||('A'<=data[i]&&'Z'>=data[i])) {
		//	printf("%c",data[i]);	
		//}else {
			printf("\\x%02x",data[i]);
		//}
		if((i+1)%align == 0 && (i+1)!=len){
			printf("\"\n\"");
		}
	}
	printf("\";\n");
	return NULL;
}


static 
unsigned char * genOpCode(unsigned char *code_addr, unsigned char mark){

	int len = 0;
	unsigned char opcode[1024] = {'0'};
	unsigned char *p = code_addr;
	while(*p != mark){
		if(*p == NULL){
			printf("opcode contains NULL byte! Null byte Offset:[%d]\n",len);
			exit(0);			
		}
		opcode[len++] = *p;
		p++;
		if(len > 1024) {
			printf("opcode is too large!!\n");
			exit(0);
		}
	}
	opcode[len] = '\x00';
	return opcode;

}


static 
void safe_strncpy( unsigned char *dst, unsigned char *src, int count){
	
	count = -count;
	__asm{
		CLD
		XOR ecx,ecx
		sub ecx,count
		MOV esi,src
		MOV edi,dst
		REP MOVSB
	}

}