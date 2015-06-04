// Includes and Namespaces
#include "KMSPID.h"

#pragma region Structs

// HostType and OSBuild
static const struct KMSHostOS { WORD Type; WORD Build; } HostOS[] =
{
    { 55041, 7601 }, // Windows Server 2008 R2 SP1
    {  5426, 9200 }, // Windows Server 2012
    {  6401, 9600 }, // Windows Server 2012 R2
};

// GroupID and PIDRange
static const struct PKEYCONFIG { WORD GroupID; DWORD RangeMin; DWORD RangeMax; } pkeyconfig[] = {
    { 206, 152000000, 152999999 }, // Windows Server 2012 KMS Host pkeyconfig, actual max is 191999999
    { 206, 271000000, 271999999 }, // Windows Server 2012 R2 KMS Host pkeyconfig, actual max is 310999999
    {  96, 199000000, 201999999 }, // Office2010 KMS Host pkeyconfig, actual max is 217999999
    { 206, 234000000, 234999999 }, // Office2013 KMS Host pkeyconfig, actual max is 255999999
};

#pragma endregion

#pragma region Defines

// Defines
static const GUID APP_ID_WINDOWS  = {0x55C92734, 0xD682, 0x4D71, {0x98, 0x3E, 0xD6, 0xEC, 0x3F, 0x16, 0x05, 0x9F}};
static const GUID APP_ID_OFFICE14 = {0x59A52881, 0xA989, 0x479D, {0xAF, 0x46, 0xF2, 0x75, 0xC6, 0x37, 0x06, 0x63}};
static const GUID APP_ID_OFFICE15 = {0x0FF1CE15, 0xA989, 0x479D, {0xAF, 0x46, 0xF2, 0x75, 0xC6, 0x37, 0x06, 0x63}};

#define HOST_SERVER2008R2 0
#define HOST_SERVER2012 1
#define HOST_SERVER2012R2 2

#define PKEYCONFIG_SERVER2012_CSVLK 0
#define PKEYCONFIG_SERVER2012R2_CSVLK 1
#define PKEYCONFIG_OFFICE2010_CSVLK 2
#define PKEYCONFIG_OFFICE2013_CSVLK 3

// Minimum possible activation date for each Microsoft products (in UTC seconds)
#define MinDateServer2008R2 ((time_t)1297875600LL) // Available on February 16, 2011 through TechNet or MSDN
#define MinDateServer2012   ((time_t)1346778000LL) // Available on September 4, 2012 through TechNet or MSDN
#define MinDateOffice2013   ((time_t)1351098000LL) // Available on October 24, 2012 through TechNet or MSDN
#define MinDateServer2012R2 ((time_t)1382029200LL) // Available on October 17, 2013 through TechNet or MSDN

// Macros
#define countof( array ) ( sizeof( array )/sizeof( array[0] ) )

#pragma endregion

using namespace std;

// Get GroupID and PIDRange for the specified AppID and KMS Protocol Version
static const PKEYCONFIG *GetKMSHostPkeyConfig(REQUEST* const Request)
{
	if (Request->ApplicationId == APP_ID_WINDOWS)
		return (Request->MajorVer == 6 ? &pkeyconfig[PKEYCONFIG_SERVER2012R2_CSVLK] : &pkeyconfig[PKEYCONFIG_SERVER2012_CSVLK]);

	if (Request->ApplicationId == APP_ID_OFFICE15)
		return &pkeyconfig[PKEYCONFIG_OFFICE2013_CSVLK];

	if (Request->ApplicationId == APP_ID_OFFICE14)
		return &pkeyconfig[PKEYCONFIG_OFFICE2010_CSVLK];

	return &pkeyconfig[PKEYCONFIG_SERVER2012_CSVLK];
}

// Calculate Minimum Possible Date of KMS Host
static const time_t GetMinKMSHostBuildDate(int HostIndex, REQUEST* const Request)
{
	// Request is KMS V6 or Server 2012 R2 Build # is used
	if (Request->MajorVer == 6 || HostIndex == HOST_SERVER2012R2)
		return MinDateServer2012R2;

	// Request is Office 2013 (Both V4 and V5)
	if (Request->ApplicationId == APP_ID_OFFICE15)
		return MinDateOffice2013;

	// Request is KMS V5 or Server 2012 Build # is used
	if (Request->MajorVer == 5 || HostIndex == HOST_SERVER2012)
		return MinDateServer2012;

	// Otherwise, Request is KMS V4 (Office 2010/Vista/7) and Server 2008 R2 Build # is used
	return MinDateServer2008R2;
}

// Random Number Generator
BOOL GetRandomBytes(BYTE *RandomBuffer, DWORD RandomBufferLength)
{
	BOOL success = FALSE;
	HCRYPTPROV hProv = NULL;

	success = CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) && 
			  CryptGenRandom(hProv, RandomBufferLength, RandomBuffer);

	if (hProv)
		CryptReleaseContext(hProv, 0);

	return success;
}

void CreateKMSPID(WCHAR* const KMSPID, REQUEST* const Request)
{
	// Random Number Buffer
	DWORD RandomNumber[4];
	GetRandomBytes((BYTE *)RandomNumber, sizeof(RandomNumber));

	// Choose KMS HostOS
	int HostIndex = RandomNumber[0] % countof(HostOS);
	const KMSHostOS *host = &HostOS[HostIndex];

	// Set Product Specific Base pkeyconfig (use Windows if unknown product)
	const PKEYCONFIG *config = GetKMSHostPkeyConfig(Request);

	// Generate Random ID
	int RandomID = config->RangeMin + RandomNumber[1] % (config->RangeMax - config->RangeMin);

	// Generate Part 5: License Channel (00=Retail, 01=Retail, 02=OEM, 03=Volume(GVLK,MAK)) - always 03
	DWORD LicenseChannel = 3;

	// Generate Part 6: Language - use system default language
	DWORD LanguageCode = GetSystemDefaultLCID();

	// Get Product Specific Minimum Activation Date
	time_t MinDate = GetMinKMSHostBuildDate(HostIndex, Request);

	// Get Maximum Possible Value of Activation Date
	time_t MaxDate = time(NULL) - 86400; // limit latest activation date to yesterday

	// Generate Random Date between MinDate and MaxDate
	time_t RandomDate = ((ULONG64 *)RandomNumber)[1] & 0x7FFFFFFFFFFFFFFFULL;
	time_t GeneratedDate = MinDate + RandomDate % (MaxDate - MinDate);
	struct tm Date;
	localtime_s(&Date, &GeneratedDate);
	
	StringCchPrintfW(KMSPID, PID_BUFFER_SIZE, L"%05u-%05u-%03u-%06u-%02u-%u-%04u.0000-%03d%04d",
		host->Type, config->GroupID, RandomID / 1000000, RandomID % 1000000, LicenseChannel,
		LanguageCode, host->Build, Date.tm_yday+1, Date.tm_year+1900);
}

// Get Application Specific KMS PID from the Registry (KMS Server Service Only)
void GetKMSPID(WCHAR* const KMSPID, REQUEST* const Request)
{
	// Open Registry Key
	HKEY hKey;
    DWORD bufferSize = 256;
	WCHAR buffer[256] = {0};

	// Get ClientAppID as String
	WCHAR ClientAppID[GUID_BUFFER_SIZE];
	StringCchPrintfW(ClientAppID, GUID_BUFFER_SIZE, L"%08X-%04hX-%04hX-%02X%02X-%02X%02X%02X%02X%02X%02X", Request->ApplicationId.Data1, Request->ApplicationId.Data2, Request->ApplicationId.Data3, Request->ApplicationId.Data4[0], Request->ApplicationId.Data4[1], Request->ApplicationId.Data4[2], Request->ApplicationId.Data4[3], Request->ApplicationId.Data4[4], Request->ApplicationId.Data4[5], Request->ApplicationId.Data4[6], Request->ApplicationId.Data4[7]);

	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Services\\KMSServerService\\Parameters\\KMSPID"), NULL, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		// Get Registry Value
		if (RegQueryValueExW(hKey, ClientAppID, NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS)
		{
			if (regex_match(buffer, wregex(L"^([0-9]{5})-([0-9]{5})-([0-9]{3})-([0-9]{6})-([0-9]{2})-([0-9]{4,5})-([0-9]{4}).([0-9]{4})-([0-9]{7})$")))
			{
				// Close Registry Key
				RegCloseKey(hKey);

				// Apply Setting
				StringCchCopyW(KMSPID, PID_BUFFER_SIZE, buffer);
			}
		}
		
		// Close Registry Key
		RegCloseKey(hKey);
	}
	else
	{
		// Return Empty KMSPID
		StringCchCopyW(KMSPID, PID_BUFFER_SIZE, L"");
	}
}