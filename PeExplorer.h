#pragma once
#define VerifyDosHeader(signature) (signature == (WORD)'ZM' ? true : false)
#define VerifyPeHeader(signature) (signature == (WORD)'EP' ? true : false)

class PeExplorer
{
public:

	bool Explore(PVOID pPe);
	bool Explore(const char* FileName, DWORD ExtraSize);
	PIMAGE_SECTION_HEADER GetSectionByName(const char* SectionName);
	PIMAGE_SECTION_HEADER GetSectionByCharacteristics(DWORD Characteristics);
	PIMAGE_SECTION_HEADER GetLastSection();
	~PeExplorer();

	std::vector<PIMAGE_SECTION_HEADER> GetSectionList();
	PIMAGE_DOS_HEADER GetDosHeader();
	PIMAGE_NT_HEADERS GetNtHeaders();
	PIMAGE_FILE_HEADER GetFileHeader();
	PIMAGE_OPTIONAL_HEADER GetOptionalHeader();
	
	LPVOID		pMap = nullptr;

private:
	
	DWORD		FileSize = -1;	

	PIMAGE_DOS_HEADER					pDosHeader = nullptr;
	PIMAGE_NT_HEADERS					pNtHeaders = nullptr;
	PIMAGE_FILE_HEADER					pFileHeader = nullptr;
	PIMAGE_OPTIONAL_HEADER				pOptionalHeader = nullptr;
	std::vector<PIMAGE_SECTION_HEADER>	SectionHeaderList;
};
