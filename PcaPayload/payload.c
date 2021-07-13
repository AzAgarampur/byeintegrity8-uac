#include <Windows.h>

BOOL WINAPI DllMain(
	HINSTANCE hInstance,
	DWORD reason,
	LPVOID reserved
)
{
	UNREFERENCED_PARAMETER(reserved);

	if (reason == DLL_PROCESS_ATTACH) {
		PWSTR system32;
	}

	return TRUE;
}