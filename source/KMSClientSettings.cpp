// Includes and Namespaces
#include "KMSClientSettings.h"

// KMS Client Parameters
WCHAR KMSClientSettings::KMSHost[256];
WCHAR KMSClientSettings::KMSPort[PORT_BUFFER_SIZE];
WCHAR KMSClientSettings::KMSClientMode[256];

// KMS Client Identification Data
DWORD KMSClientSettings::RequiredClientCount;
WORD KMSClientSettings::KMSProtocolMajorVersion;
WORD KMSClientSettings::KMSProtocolMinorVersion;
DWORD KMSClientSettings::KMSClientLicenseStatus;
WCHAR KMSClientSettings::KMSClientAppID[GUID_BUFFER_SIZE];
WCHAR KMSClientSettings::KMSClientSkuID[GUID_BUFFER_SIZE];
WCHAR KMSClientSettings::KMSClientKMSCountedID[GUID_BUFFER_SIZE];

// KMS Client Program Control
bool KMSClientSettings::RunAsService;

// Set Default Settings
void KMSClientSettings::Initialize() 
{
	StringCchCopyW(KMSHost, 256, L"127.0.0.2");
	StringCchCopyW(KMSPort, PORT_BUFFER_SIZE, L"1688");
	StringCchCopyW(KMSClientMode, 256, L"Windows");
	RequiredClientCount = 25;
	KMSProtocolMajorVersion = 4;
	KMSProtocolMinorVersion = 0;
	KMSClientLicenseStatus = 2;
	StringCchCopyW(KMSClientAppID, GUID_BUFFER_SIZE, L"55c92734-d682-4d71-983e-d6ec3f16059f");
	StringCchCopyW(KMSClientSkuID, GUID_BUFFER_SIZE, L"cfd8ff08-c0d7-452b-9f60-ef5c70c32094");
	StringCchCopyW(KMSClientKMSCountedID, GUID_BUFFER_SIZE, L"212a64dc-43b1-4d3d-a30c-2fc69d2095c6");
	RunAsService = false;
};