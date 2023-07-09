#include <Windows.h>
#include <iostream>

/*
	References
	- https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time
	- https://gist.github.com/hasherezade/455975e52fd8eb507ed3f54d86352d84
	- https://m0uk4.gitbook.io/notebooks/mouka/windowsinternal/ssdt-hook
*/

/**
* Offset = RVA - section VirtualAddress + section PointerToRawData
*/
ULONG RvaToOffset(_In_ PIMAGE_NT_HEADERS NtHeaders, _In_ ULONG Rva)
{
	PIMAGE_SECTION_HEADER SectionHeaders = IMAGE_FIRST_SECTION(NtHeaders);
	USHORT NumberOfSections = NtHeaders->FileHeader.NumberOfSections;
	ULONG Result = 0;
	
	for (USHORT i = 0; i < NumberOfSections; ++i)
	{
		if (SectionHeaders->VirtualAddress <= Rva && SectionHeaders->VirtualAddress + SectionHeaders->Misc.VirtualSize > Rva)
		{
			Result = Rva - SectionHeaders->VirtualAddress + SectionHeaders->PointerToRawData;

			break;
		}
		SectionHeaders++;
	}
	return Result;
}


/**
 * @brief This function calculates the address of data (Ex. Import Directory) in the PE image's file region (data stored on disk).
 *
 * Given a pointer to a buffer that contains a PE file, this function parses the PE header
 * then searches for a section containing the data's RVA, and calculates the address of the data in the file region.
 *
 * @param BaseAddress The base address of the buffer that contains the PE file.
 * @param NtHeaderPtr Pointer to the NT header of the PE file.
 * @param Rva The relative virtual address, relative to the base address of a module.
 * @return The address in the image's file region.
 */
PVOID TranslateAddress(_In_ PBYTE BaseAddress, _In_ PIMAGE_NT_HEADERS NtHeaderPtr, _In_ DWORD Rva) {
	
	// Find the section containing the RVA.
	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeaderPtr);
	
	for (int i = 0; i < NtHeaderPtr->FileHeader.NumberOfSections; i++, SectionHeader++) {
		
		// If the RVA is within this section.
		if (Rva >= SectionHeader->VirtualAddress && Rva < SectionHeader->VirtualAddress + SectionHeader->Misc.VirtualSize) {

			// (Rva - SectionHeader->VirtualAddress), this calculates the offset from the start of the section.
			// SectionHeader->PointerToRawData is the offset from the start of the file to the start of the section in the file region.
			
			return BaseAddress + SectionHeader->PointerToRawData + (Rva - SectionHeader->VirtualAddress);
		}

	}

	return NULL;
}


/**
* Dump syscall IDs from Win32k.sys
*/
int main() {

	// Open a handle to Win32k.sys
	HANDLE Win32kFileHandle = CreateFileW(L"C:\\Windows\\System32\\win32k.sys", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (Win32kFileHandle == INVALID_HANDLE_VALUE) {
		printf("Failed to open handle to win32k.sys with error code: %lu\n", GetLastError());
		return -1;
	}

	// Get the size of the file
	DWORD Win32kFileSize = GetFileSize(Win32kFileHandle, NULL);
	
	if (Win32kFileSize == INVALID_FILE_SIZE) {
		printf("Failed to get size of win32k.sys with error code: %lu\n", GetLastError());
		return -1;
	}

	printf("Win32k.sys size: %lu bytes\n", Win32kFileSize);
	
	// Allocate a buffer to read into.
	BYTE* buffer = new BYTE[Win32kFileSize];

	if (!ReadFile(Win32kFileHandle, buffer, Win32kFileSize, NULL, NULL)) {
		printf("Failed to read win32k.sys with error code: %lu\n", GetLastError());
		return -1;
	}

	// Get the PE headers
	auto dosHeader = (PIMAGE_DOS_HEADER)buffer;
	auto ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)buffer + dosHeader->e_lfanew);

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Invalid DOS header");
		return -1;
	}

	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		printf("Invalid NT header");
		return -1;
	}

	// Get the export directory
	PIMAGE_DATA_DIRECTORY ImageDirectories = ntHeader->OptionalHeader.DataDirectory;
	
	ULONG ExportDirRva = ImageDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	ULONG ExportDirSize = ImageDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	ULONG ExportOffset = RvaToOffset(ntHeader, ExportDirRva);

	PIMAGE_EXPORT_DIRECTORY ExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(TranslateAddress(buffer, ntHeader, ExportDirRva));
		//reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(buffer + ExportOffset);
	printf("Export number of function %i\n", ExportDirectory->NumberOfFunctions);
	
	PULONG AddressOfFunctions = (PULONG)(buffer + RvaToOffset(ntHeader, ExportDirectory->AddressOfFunctions));
	PUSHORT AddressOfNameOrdinals = (PUSHORT)(buffer + RvaToOffset(ntHeader, ExportDirectory->AddressOfNameOrdinals));
	PULONG AddressOfNames = (PULONG)(buffer + RvaToOffset(ntHeader, ExportDirectory->AddressOfNames));

	for (int i = 0; i < ExportDirectory->NumberOfNames; i++) {
		
		ULONG NameOffset = RvaToOffset(ntHeader, AddressOfNames[i]);
		if (NameOffset == 0)
			continue;

		PCSTR FunctionName = (PSTR)(buffer + NameOffset);
	    ULONG FunctionRva = AddressOfFunctions[AddressOfNameOrdinals[i]];
		
		/*
		if (FunctionRva >= ExportDirRva && FunctionRva < ExportDirRva + ExportDirSize)
			continue;
		*/

		// Could implement a better name check here
		if (FunctionName[0] == '_' && FunctionName[1] == '_') {
			
			ULONG ExportOffset = RvaToOffset(ntHeader, FunctionRva);

			// Reverse endian + 1 byte gives us our syscall ID.
			ULONG SyscallID = *(ULONG*)(buffer + ExportOffset + 0x1);
			std::cout << FunctionName << std::endl;		
			std::cout << std::hex << SyscallID << std::endl;
			
			
			/*
			if (strcmp(FunctionName, "__win32kstub_NtUserGetForegroundWindow") == 0) {
				std::cout << FunctionName << std::endl;
				ULONG SyscallID = *(ULONG*)(buffer + ExportOffset + 0x1);
				std::cout << std::hex << SyscallID << std::endl;
			}
			*/

		}

	}
	
	// Clean up.
	delete[] buffer;
	CloseHandle(Win32kFileHandle);
	
	system("pause");
	return 0;
}