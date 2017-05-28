#include "includes.h"


const char shell[] = {  0xB8, 0xAA, 0xAA, 0xAA, 0xAA,			// mov eax, 0xAAAAAAAA
			0x89, 0xC1,					// mov ecx, eax
			0x81, 0xC1, 0xAA, 0xAA, 0xAA, 0xAA,		// add ecx, 0xAAAAAAAA
			0xBA, 0xAA, 0xAA, 0xAA, 0xAA,			// mov edx, 0xAAAAAAAA
								//	l1:
			0x30, 0x10,					// xor byte[eax], edx
			0x40,						// inc eax
			0x39, 0xC8,					// cmp eax, ecx
			0x75, 0xF9,					// jne l1
			0x68, 0xAA, 0xAA, 0xAA, 0xAA,			// push 0xAAAAAAAA
			0xC3 };						// ret

DWORD Size = sizeof(shell);


int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		printf("usage: filename.exe");
		return 0;
	}
	
	PeExplorer* g_pPe = new PeExplorer();
	
	if (!g_pPe->Explore(argv[1], Size))
	{
		std::cin.get();
		return 0;
	}
	
	PeCrypter* g_pCrypt = new PeCrypter(g_pPe);
	if (!g_pCrypt->Crypt(shell, Size))
	{
		std::cin.get();
		return 0;
	}
	

	g_pPe->~PeExplorer();
	g_pCrypt->~PeCrypter();

	
	
	std::cin.get();
	return 0;
}
