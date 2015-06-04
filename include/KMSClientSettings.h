//---------------------------------------------------------------------------
// Header Guard
#pragma once

// Includes and Namespaces
#include <windows.h>
#include <Strsafe.h>
#include "CoreKMS.h"
//---------------------------------------------------------------------------
// Class Prototypes

// Contain all KMS Client Parameters and Settings.
class KMSClientSettings
{
public:
	// KMS Client Parameters
	static WCHAR KMSHost[256];
	static WCHAR KMSPort[PORT_BUFFER_SIZE];
	static WCHAR KMSClientMode[256];

	// KMS Client Identification Data
	static DWORD RequiredClientCount;
	static WORD KMSProtocolMajorVersion;
	static WORD KMSProtocolMinorVersion;
	static DWORD KMSClientLicenseStatus;
	static WCHAR KMSClientAppID[GUID_BUFFER_SIZE];
	static WCHAR KMSClientSkuID[GUID_BUFFER_SIZE];
	static WCHAR KMSClientKMSCountedID[GUID_BUFFER_SIZE];

	// KMS Client Program Control
	static bool RunAsService;

	// Set Default Settings
	static void Initialize();
};
//---------------------------------------------------------------------------