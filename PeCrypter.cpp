#include "includes.h"



PeCrypter::~PeCrypter()
{
	TextSection = nullptr;
	LastSection = nullptr;
	g_pPe = nullptr;
	Key = 0;
}

PeCrypter::PeCrypter(PeExplorer* Pe)
{
	g_pPe = Pe;
	srand(time(NULL));
	Key = rand() % 255;

	TextSection = g_pPe->GetSectionByCharacteristics(IMAGE_SCN_CNT_CODE);
	TextSection->Characteristics |= IMAGE_SCN_MEM_WRITE;

	LastSection = g_pPe->GetLastSection();

}

template <typename T>
bool PeCrypter::PatchBytesByVal(DWORD DestAddress, DWORD SizeOfCode, LPVOID SrcAddress, T ValToLookFor)
{
	for (int i = 0; i < SizeOfCode; ++i)
	{
		if (*(T*)(DestAddress + i) == ValToLookFor)
		{
			memcpy((PVOID)(DestAddress + i), SrcAddress, sizeof(T));
			return true;
		}
	}
	return false;
}

void PeCrypter::EncryptBytes(DWORD Source, DWORD Size)
{
	for (int i = 0; i < Size; ++i)
		*(BYTE*)(Source + i) ^= Key;
}


bool PeCrypter::Crypt(const char* ShellPtr, DWORD ShellSize)
{
	printf("Crypting .text section...\n");

	srand(time(NULL));
	Key = rand() % 255;			// Generate random key

	TextSection = g_pPe->GetSectionByCharacteristics(IMAGE_SCN_CNT_CODE);	// Get code section, the name of it might variate. Therefore search for characteristics
	if (TextSection == nullptr)
		goto cleanup;
	TextSection->Characteristics |= IMAGE_SCN_MEM_WRITE;		// Add write characteristics for encrypting the section

	LastSection = g_pPe->GetLastSection();		// Get last section for adding stub
	if (LastSection == nullptr)
		goto cleanup;

	EncryptBytes((DWORD)g_pPe->pMap + TextSection->PointerToRawData, TextSection->SizeOfRawData);	// Encrypt section, keep in mind that the base of the PE mapped into memory is based at pMap not ImageBase
													// Encrypt the whole section, including alignment, not only VirtualSize

	LastSection->Characteristics |= IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;	// Add characteristics for LastSection, preparing it for stub

	DWORD NewEIP = LastSection->VirtualAddress + LastSection->Misc.VirtualSize;			// NewEIP should be the VirtualAddress + VirtualSize of the section before adding the stub size
	DWORD OldEIP = g_pPe->GetOptionalHeader()->AddressOfEntryPoint + g_pPe->GetOptionalHeader()->ImageBase;
	g_pPe->GetOptionalHeader()->AddressOfEntryPoint = NewEIP;

	LastSection->Misc.VirtualSize += ShellSize;			// Add stub size

	DWORD OldRawSize = LastSection->SizeOfRawData;

	DWORD NewRawSize = AlignUp(LastSection->Misc.VirtualSize, g_pPe->GetOptionalHeader()->FileAlignment);	// Align the section with FileAlignment. The RawDataSize should be dividable by the FileAlignment
	LastSection->SizeOfRawData = NewRawSize;								// Thats why it should be the VirtualSize rounded up to be dividable by FileAlignment

	g_pPe->GetOptionalHeader()->SizeOfImage += (NewRawSize - OldRawSize);	// Add the potentially added size of the section RawSize to SizeOfImage

	DWORD Dst = (DWORD)g_pPe->pMap + LastSection->Misc.VirtualSize - ShellSize + LastSection->PointerToRawData;	// The destination to copy the stub to should be the base of the mapped PE + Pointer2RawData - StubSize
															// This will point to the end of the section VirtualSize and to the beginning of the stub

	DWORD size = TextSection->SizeOfRawData;	// The size to be decrypted should be the RawSize of the code section

	DWORD start = TextSection->VirtualAddress + g_pPe->GetOptionalHeader()->ImageBase;	// And the start address of the decryption should be the VirtualAddress of the code section + ImageBase, for it's loaded.


	memcpy((PVOID)Dst, ShellPtr, ShellSize);

	if (!PatchBytesByVal<DWORD>(Dst, ShellSize, &start, 0xAAAAAAAA))	// Replace the first DWORD of A's with the start address
		goto cleanup;
	if (!PatchBytesByVal<DWORD>(Dst, ShellSize, &size, 0xAAAAAAAA))		// Replace the second DWORD of A's with the size
		goto cleanup;
	if (!PatchBytesByVal<DWORD>(Dst, ShellSize, &Key, 0xAAAAAAAA))		// Replace the third DWORD of A's with the key
		goto cleanup;
	if (!PatchBytesByVal<DWORD>(Dst, ShellSize, &OldEIP, 0xAAAAAAAA))	// Replace the fourth DWORD of A's with the Old Entry Point to return to
		goto cleanup;
		
	return true;

cleanup:
	PeCrypter::~PeCrypter();
	return false;
}
