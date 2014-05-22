#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MARK	0xCC


static void __declspec(naked) testOpcode() {

	__asm{
	
		xor	eax,eax
		inc	eax
		pushad
		jmp	eax
		pushad
		ret
	}

	//½áÊø±êÖ¾
	__asm{__emit MARK}

}



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



int main(int arhc, char **argv) {
	
	int len;
	unsigned char buf[1024];
	unsigned char *opcode = genOpCode(testOpcode,MARK);
	memset(buf,0,1024);
	len = strlen(opcode);
	sprintf(buf,"unsigned char opcode[%d]=",len);
	out_C_format(opcode,len,buf,16);
	return 0;

}