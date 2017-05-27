#pragma once
class PeCrypter
{
public:	
	~PeCrypter();
	PeCrypter(PeExplorer* g_pPe);
	bool Crypt(const char* ShellPtr, DWORD ShellSize);

private:
	DWORD AlignDown(DWORD val, DWORD align)
	{
		return (val & ~(align - 1));
	}

	DWORD AlignUp(DWORD val, DWORD align)
	{
		return ((val & (align - 1)) ? AlignDown(val, align) + align : val);
	}

	template <typename T>
	bool PatchBytesByVal(DWORD DestAddress, DWORD SizeOfCode, LPVOID SrcAddress, T ValToLookFor);
	void EncryptBytes(DWORD Source, DWORD Size);

	DWORD					Key = 0;
	PIMAGE_SECTION_HEADER	LastSection = nullptr;
	PIMAGE_SECTION_HEADER	TextSection = nullptr;
	PeExplorer*				g_pPe = nullptr;
};

