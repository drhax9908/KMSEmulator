// Includes and Namespaces
#include "KMSHWID.h"
using namespace std;

// Get Application Specific KMSHWID from the Registry (KMS Server Service Only)
void GetKMSHWID(PQWORD KMSHWID, REQUEST* const Request)
{
	// Open Registry Key
	HKEY hKey;
    DWORD bufferSize = 256;
	WCHAR buffer[256] = {0};

	// Get ClientAppID as String
	WCHAR ClientAppID[GUID_BUFFER_SIZE];
	StringCchPrintfW(ClientAppID, GUID_BUFFER_SIZE, L"%08X-%04hX-%04hX-%02X%02X-%02X%02X%02X%02X%02X%02X", Request->ApplicationId.Data1, Request->ApplicationId.Data2, Request->ApplicationId.Data3, Request->ApplicationId.Data4[0], Request->ApplicationId.Data4[1], Request->ApplicationId.Data4[2], Request->ApplicationId.Data4[3], Request->ApplicationId.Data4[4], Request->ApplicationId.Data4[5], Request->ApplicationId.Data4[6], Request->ApplicationId.Data4[7]);

	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Services\\KMSServerService\\Parameters\\KMSHWID"), NULL, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		// Get Registry Value
		if (RegQueryValueExW(hKey, ClientAppID, NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS)
		{
			if (regex_match(buffer, wregex(L"^[a-fA-F0-9]{16}$")))
			{
				// Close Registry Key
				RegCloseKey(hKey);

				// Apply Setting
				*KMSHWID = wcstoull(buffer, NULL, 16);
			}
		}
		
		// Close Registry Key
		RegCloseKey(hKey);
	}
	else
	{
		// Return NULL KMSHWID
		*KMSHWID = 0x0;
	}
}