#include <iostream>
#include <string>
#include <locale>
#include <codecvt>
#include <Windows.h>

#include "Binder.h"
#include "console.h"
#include "helper.h"

#define CONSOLE_WINDOW_TITLE L"Arkhos v1.0"

VOID CreateConsole() {
	::AllocConsole();
	::AttachConsole(::GetCurrentProcessId());
	::SetConsoleTitle(CONSOLE_WINDOW_TITLE);
	freopen("CON", "w", stdout);
	freopen("CON", "w", stderr);
}

VOID DestroyConsole() {
	::FreeConsole();
}

VOID PauseConsole() {
	WCHAR szTmp[2];
	DWORD dwRead = 0;

	//::WriteConsole
	std::wcerr << L"Press Enter to continue...";
	::ReadConsole(::GetStdHandle(STD_INPUT_HANDLE), szTmp, 1, &dwRead, NULL);
}

/*
* Console syntax: argv[0] -f [TARGET FILENAME] -p [PAYLOAD FILENAME] -o [OUTPUT FILENAME]
*/
VOID PrintUsage(LPCWSTR self) {
	std::wcerr << self << L" -f [TARGET FILENAME] -p [PAYLOAD FILENAME] -o [OUTPUT FILENAME]\n";
	PauseConsole();
	ExitProcess(1);
}

int ConsoleMain(int argc, wchar_t *argv[]) {
	// get a console window
	CreateConsole();

	// check correct number of parameters (3)
	if (argc < 4 || argc < 6)
		PrintUsage(argv[0]);

	// parse command line
	std::wstring targetFileName;
	std::wstring outputFileName;
	std::wstring payloadFileName;
	for (int i = 0; i < argc; i++) {
		// target process name
		if (!wcsicmp(argv[i], L"-f"))
			targetFileName = argv[i + 1];
		else if (!wcsicmp(argv[i], L"-o"))
			outputFileName = argv[i + 1];
		else if (!wcsicmp(argv[i], L"-p"))
			payloadFileName = argv[i + 1];
	}

	// reject if both are either empty or not empty
	//if (targetFileName.empty() || payloadFileName.empty())
	//	PrintUsage(argv[0]);

	if (outputFileName.empty())
		outputFileName = L"output.exe";

	Binder::GetInstance()->SetTargetFile(targetFileName);
	Binder::GetInstance()->SetPayloadFile(payloadFileName);
	Binder::GetInstance()->SetOutputFile(outputFileName);
	Binder::GetInstance()->Bind();

	// clean up

	// free console window
	DestroyConsole();

	return 0;
}