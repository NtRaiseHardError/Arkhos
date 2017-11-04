#include <string>
#include <Windows.h>
#include <CommCtrl.h>
#include <TlHelp32.h>

#include "Binder.h"
#include "gui.h"
#include "helper.h"
#include "resource.h"

#pragma comment(lib, "ComCtl32.lib")

#define RED RGB(0xFF, 0, 0)
#define GREEN RGB(0, 0xFF, 0)

bool bTargetFile = false;
bool bPayloadFile = false;
bool bOutputFile = false;

void OutputString(HWND hDlg, LPCWSTR fmt, ...) {
	va_list args;
	va_start(args, fmt);

	WCHAR szOutput[MAX_PATH];
	vswprintf(szOutput, fmt, args);
	::SetDlgItemText(hDlg, IDC_STATIC1, szOutput);

	va_end(args);
}

void UpdateProgressBar(HWND hDlg, int nValue, bool bError) {
	if (bError)
		::SendMessage(::GetDlgItem(hDlg, IDC_PROGRESS1), PBM_SETBARCOLOR, 0, static_cast<LPARAM>(RED));
	else
		::SendMessage(::GetDlgItem(hDlg, IDC_PROGRESS1), PBM_SETBARCOLOR, 0, static_cast<LPARAM>(GREEN));

	// -1 means keep same value
	if (nValue >= 0)
		::SendMessage(::GetDlgItem(hDlg, IDC_PROGRESS1), PBM_SETPOS, static_cast<WPARAM>(nValue), 0);
}

bool SaveFile(HWND hDlg, std::wstring& szSaveFileName) {
	LPOPENFILENAME lpOfn = new OPENFILENAME;
	WCHAR szFileName[MAX_PATH] = L"";

	::ZeroMemory(lpOfn, sizeof(OPENFILENAME));

	lpOfn->lStructSize = sizeof(OPENFILENAME);
	lpOfn->hwndOwner = hDlg;
	lpOfn->lpstrFilter = L"Executable Files (*.exe)\0*.txt\0All Files (*.*)\0*.*\0";
	lpOfn->lpstrFile = szFileName;
	lpOfn->nMaxFile = MAX_PATH;
	lpOfn->Flags = OFN_EXPLORER | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT | OFN_CREATEPROMPT;
	lpOfn->lpstrDefExt = L"exe";

	if (!::GetSaveFileName(lpOfn))
		return false;

	szSaveFileName = std::wstring(szFileName);

	delete lpOfn;

	return true;
}

bool OpenFile(HWND hDlg, std::wstring& fileName) {
	LPOPENFILENAME lpOfn = new OPENFILENAME;
	WCHAR szFileName[MAX_PATH] = L"";

	ZeroMemory(lpOfn, sizeof(OPENFILENAME));

	lpOfn->lStructSize = sizeof(OPENFILENAME);
	lpOfn->hwndOwner = hDlg;
	lpOfn->lpstrFile = szFileName;
	lpOfn->lpstrFile[0] = '\0';
	lpOfn->nMaxFile = MAX_PATH;
	lpOfn->lpstrFilter = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
	lpOfn->nFilterIndex = 1;
	lpOfn->lpstrFileTitle = NULL;
	lpOfn->nMaxFileTitle = 0;
	lpOfn->lpstrInitialDir = NULL;
	lpOfn->Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	if (!::GetOpenFileName(lpOfn))
		return false;

	fileName = szFileName;

	delete lpOfn;

	return true;
}

bool OpenOutputFile(HWND hDlg, std::wstring& fileName) {
	LPOPENFILENAME lpOfn = new OPENFILENAME;
	WCHAR szFileName[MAX_PATH] = L"";

	ZeroMemory(lpOfn, sizeof(OPENFILENAME));

	lpOfn->lStructSize = sizeof(OPENFILENAME);
	lpOfn->hwndOwner = hDlg;
	lpOfn->lpstrFile = szFileName;
	lpOfn->lpstrFile[0] = '\0';
	lpOfn->nMaxFile = MAX_PATH;
	lpOfn->lpstrFilter = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
	lpOfn->nFilterIndex = 1;
	lpOfn->lpstrFileTitle = NULL;
	lpOfn->nMaxFileTitle = 0;
	lpOfn->lpstrInitialDir = NULL;
	lpOfn->Flags = OFN_PATHMUSTEXIST;

	if (!::GetOpenFileName(lpOfn))
		return false;

	fileName = szFileName;

	delete lpOfn;

	return true;
}

INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
		case WM_INITDIALOG:
			return TRUE;
		case WM_COMMAND:
			switch (LOWORD(wParam)) {
				case IDC_SELECTTARGET: {
					std::wstring fileName;
					OpenFile(hDlg, fileName);
					::SetDlgItemText(hDlg, IDC_EDIT1, fileName.c_str());
					Binder::GetInstance()->SetTargetFile(fileName);
					bTargetFile = true;
					if (bTargetFile && bPayloadFile && bOutputFile) {
						EnableWindow(::GetDlgItem(hDlg, IDC_BIND), true);
						OutputString(hDlg, L"Ready to bind.");
					}
					break;
				}
				case IDC_SELECTPAYLOAD: {
					std::wstring fileName;
					OpenFile(hDlg, fileName);
					::SetDlgItemText(hDlg, IDC_EDIT2, fileName.c_str());
					Binder::GetInstance()->SetPayloadFile(fileName);
					bPayloadFile = true;
					if (bTargetFile && bPayloadFile && bOutputFile) {
						EnableWindow(::GetDlgItem(hDlg, IDC_BIND), true);
						OutputString(hDlg, L"Ready to bind.");
					}
					break;
				}
				case IDC_SELECTOUTPUT: {
					std::wstring fileName;
					OpenOutputFile(hDlg, fileName);
					::SetDlgItemText(hDlg, IDC_EDIT3, fileName.c_str());
					Binder::GetInstance()->SetOutputFile(fileName);
					bOutputFile = true;
					if (bTargetFile && bPayloadFile && bOutputFile) {
						EnableWindow(::GetDlgItem(hDlg, IDC_BIND), true);
						OutputString(hDlg, L"Ready to bind.");
					}
					break;
				}
				case IDC_BIND:
					OutputString(hDlg, L"Binding...");
					Binder::GetInstance()->Bind();
					OutputString(hDlg, L"Done.");
					break;
			}
			break;

		case WM_CLOSE:
			::DestroyWindow(hDlg);
			return TRUE;

		case WM_DESTROY:
			::PostQuitMessage(0);
			return TRUE;
	}

	return FALSE;
}

int GuiMain(HINSTANCE hInstance) {
	HWND hDlg = ::CreateDialogParam(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), 0, DialogProc, 0);
	::ShowWindow(hDlg, SW_SHOW);

	MSG msg;
	BOOL ret;
	while ((ret = ::GetMessage(&msg, 0, 0, 0)) != 0) {
		if (ret == -1)
			return -1;

		if (!IsDialogMessage(hDlg, &msg)) {
			::TranslateMessage(&msg);
			::DispatchMessage(&msg);
		}
	}

	return 0;
}