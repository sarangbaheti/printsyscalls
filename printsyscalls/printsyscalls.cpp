//	reference:
//	https://www.evilsocket.net/2014/02/11/on-windows-syscall-mechanism-and-syscall-numbers-extraction-methods/
//

#include <stdio.h>
#include <Windows.h>
#define IS_ADDRESS_BETWEEN( left, right, address ) ( (address) >= (left) && (address) < (right) )
PIMAGE_SECTION_HEADER SectionByRVA(PIMAGE_SECTION_HEADER pSections, DWORD dwSections, DWORD rva)
{
	PIMAGE_SECTION_HEADER pSectionHeader = pSections;
	DWORD i;
	for (i = 0; i < dwSections; i++, pSectionHeader++)
	{
		// Is the RVA within this section?
		if (IS_ADDRESS_BETWEEN(pSectionHeader->VirtualAddress, (pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData), rva))
			return pSectionHeader;
	}
	return 0;
}
DWORD RawOffsetByRVA(PIMAGE_SECTION_HEADER pSections, DWORD dwSections, DWORD dwFileSize, DWORD rva)
{
	PIMAGE_SECTION_HEADER pSectionHeader;
	DWORD dwOffset, dwDelta;
	pSectionHeader = SectionByRVA(pSections, dwSections, rva);
	if (!pSectionHeader)
	{
		return 0;
	}
	dwDelta = rva - pSectionHeader->VirtualAddress;
	dwOffset = pSectionHeader->PointerToRawData + dwDelta;
	if (dwOffset >= dwFileSize)
		return 0;
	else
	{
		return dwOffset;
	}
}
#define GET_POINTER(RVA) ( pBuffer + RawOffsetByRVA( Sections, dwSections, dwFileSize, (RVA) ) )
int main(int argc, char* argv[])
{
	HANDLE hFile = INVALID_HANDLE_VALUE,
		hMap = NULL;
	PBYTE pBuffer = NULL, pOps = NULL;
	DWORD dwFileSize = 0,
		dwSizeOfHeaders = 0,
		dwSections = 0,
		dwBaseAddress = 0,
		dwImageSize = 0,
		dwExportRVA = 0,
		dwExportSize = 0,
		dwExportRaw = 0,
		dwExports = 0;
	PDWORD pdwFunctions, pszFunctionNames;
	PWORD  pwOrdinals;
	PIMAGE_NT_HEADERS     NTHeader;
	PIMAGE_DOS_HEADER     DOSHeader;
	PIMAGE_SECTION_HEADER Sections;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	hFile = CreateFile
	(
		L"c:\\windows\\system32\\ntdll.dll",
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "Could not open file: %08X\n", GetLastError());
		goto done;
	}
	dwFileSize = GetFileSize(hFile, NULL);
	hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMap == NULL)
	{
		fprintf(stderr, "Could not create memory map: %08X\n", GetLastError());
		goto done;
	}
	pBuffer = (PBYTE)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	if (hMap == NULL)
	{
		fprintf(stderr, "Could not obtain memory map view: %08X\n", GetLastError());
		goto done;
	}
	if (pBuffer[0] != 'M' || pBuffer[1] != 'Z')
	{
		fprintf(stderr, "Unexpected file header.\n");
		goto done;
	}
	// start reading PE headers
	DOSHeader = (PIMAGE_DOS_HEADER)pBuffer;
	NTHeader = (PIMAGE_NT_HEADERS)(pBuffer + DOSHeader->e_lfanew);
	dwSizeOfHeaders = NTHeader->OptionalHeader.SizeOfHeaders;
	dwBaseAddress = NTHeader->OptionalHeader.ImageBase;
	dwImageSize = NTHeader->OptionalHeader.SizeOfImage;
	dwSections = NTHeader->FileHeader.NumberOfSections;
	// get first section header
	Sections = (PIMAGE_SECTION_HEADER)
		(
			pBuffer +
			DOSHeader->e_lfanew +
			sizeof(IMAGE_NT_HEADERS)
			);
	// now parse the export directory
	dwExportRVA = NTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	dwExportSize = NTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	dwExportRaw = RawOffsetByRVA(Sections, dwSections, dwFileSize, dwExportRVA);
	if (!dwExportRVA || !dwExportSize || !dwExportRaw)
	{
		fprintf(stderr, "Unexpected export directory structure.\n");
		goto done;
	}
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pBuffer + dwExportRaw);
	pdwFunctions = (PDWORD)GET_POINTER(pExportDirectory->AddressOfFunctions);
	pwOrdinals = (PWORD)GET_POINTER(pExportDirectory->AddressOfNameOrdinals);
	pszFunctionNames = (PDWORD)GET_POINTER(pExportDirectory->AddressOfNames);
	dwExports = pExportDirectory->NumberOfNames;
	printf("SYSCALL   RVA       NAME\n");
	printf("-----------------------------------------------\n");
	// loop each exported symbol by name
	for (DWORD i = 0; i < pExportDirectory->NumberOfNames; ++i)
	{
		DWORD dwNameRVA = pszFunctionNames[i],
			dwApiRVA = pdwFunctions[pwOrdinals[i]],
			dwSyscall = 0,
			dwApiRaw = RawOffsetByRVA(Sections, dwSections, dwFileSize, dwApiRVA),
			dwNameRaw = RawOffsetByRVA(Sections, dwSections, dwFileSize, dwNameRVA);
		pOps = pBuffer + dwApiRaw;

		//
		//	works only on x64
		//	
		//	Check if the API entry begins with:
		//		4c8bd1          mov     r10,rcx
		//		b8bc010000      mov     eax,1BCh
		//	
		//	here 1BC is the syscall number
		//	rcx is the first parameter passed to syscall
		//
		if (pOps[0] == 0x4C && pOps[3] == 0xB8)
		{
			dwSyscall = *(DWORD *)(pOps + 4);
			printf("%08X  %08X  %s\n", dwSyscall, dwBaseAddress + dwApiRVA, pBuffer + dwNameRaw);
		}

	}
done:
	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
	}
	if (pBuffer != NULL)
	{
		UnmapViewOfFile(pBuffer);
	}
	if (hMap != NULL)
	{
		CloseHandle(hMap);
	}
	return 0;
}
