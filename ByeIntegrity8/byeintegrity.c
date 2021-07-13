#include <Windows.h>
#include <evntprov.h>

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

typedef ULONG(WINAPI* EtwEventWriteNoRegistrationPtr)(
	LPGUID providerId,
	PEVENT_DESCRIPTOR eventDescriptor,
	ULONG userDataCount,
	PEVENT_DATA_DESCRIPTOR userData);

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

int wmain(
	int argc,
	WCHAR argv[]
)
{
	if (wcscmp(argv[0], L"~"))
		return BiTriggerMain();
	int exitCode = EXIT_FAILURE;

	return exitCode;
}