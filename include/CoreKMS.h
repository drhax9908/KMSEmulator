//---------------------------------------------------------------------------
// Header Guard
#pragma once

// Includes and Namespaces
#include <windows.h>
//---------------------------------------------------------------------------
// Defines
#define MAX_RESPONSE_SIZE 512
#define MAX_REQUEST_SIZE 256 // 260
#define PID_BUFFER_SIZE 64
#define PORT_BUFFER_SIZE 6
#define GUID_BUFFER_SIZE 37
#define HASH_SIZE 16
#define HASH_SIZE_SHA256 32
#define HASH_SIZE_HMAC_SHA256 16
//---------------------------------------------------------------------------
// Typdefs
typedef unsigned long long QWORD;
typedef unsigned long long *PQWORD;
//---------------------------------------------------------------------------

// Struct Prototypes
#pragma warning( disable: 4201 )	// Disable warning C4201: nonstandard extension used : nameless struct/union
// Base Properties for KMS Client Request
struct REQUEST
{
	union
	{
		DWORD Version;					// KMS Protocol Version
		struct 
		{
			WORD MinorVer;				// KMS Protocol Minor Version
			WORD MajorVer;				// KMS Protocol Major Version
		};
	};

	DWORD IsClientVM;					// Whether or not the KMS Client is a Virtual Machine
	DWORD LicenseStatus;				// Microsoft Licensing Status Code
	DWORD GraceTime;					// The time in Minutes of the KMS Client's Licensing Grace Period
	GUID ApplicationId;					// Microsoft Product Application ID
	GUID SkuId;							// Microsoft Product SKU ID
	GUID KmsCountedId;					// Microsoft Identifier for KMS Client Request Counting and Activation
	GUID ClientMachineId;				// Unique Identifier to Distinguish KMS Clients
	DWORD RequiredClientCount;			// Number of KMS Clients that must have requested KMS Server Activation
	FILETIME RequestTime;				// Time of KMS Client Request
	GUID PreviousClientMachineId;		// Previous Client Machine ID
	WCHAR MachineName[64];				// KMS Client Network DNS Name
};

// Base Properties for KMS Server Response
struct RESPONSE
{
	union
	{
		DWORD Version;				// KMS Protocol Version
		struct 
		{
			WORD MinorVer;			// KMS Protocol Minor Version
			WORD MajorVer;			// KMS Protocol Major Version
		};
	};

	DWORD KMSPIDLength;				// Length of KMS PID
	WCHAR KMSPID[PID_BUFFER_SIZE];	// Microsoft Product Key ID for KMS Server Activated Product Key
	GUID ClientMachineId;			// Unique Identifier of KMS Client
	FILETIME RequestTime;			// Time of KMS Client Request
	DWORD KMSCurrentCount;			// Number of KMS Clients that currently have requested KMS Server Activation
	DWORD VLActivationInterval;		// The time in Minutes that Unactivated KMS Clients will wait before requesting Activation
	DWORD VLRenewalInterval;		// The time in Minutes that Activated KMS Clients will wait before requesting Reactivation
};

// KMS Client Request V4 Object
struct REQUEST_V4
{
	REQUEST RequestBase;	// Unhashed KMS Client Request Data
	BYTE Hash[HASH_SIZE];	// MAC Hash of KMS Client Request Data
};

// KMS Server Response V4 Object
struct RESPONSE_V4
{
	RESPONSE ResponseBase;	// Unhashed KMS Server Response Data
	BYTE Hash[HASH_SIZE];	// MAC Hash of KMS Server Response Data
};

// KMS Client Request V5 Object
struct REQUEST_V5
{
	union
	{
		DWORD Version;		// KMS Protocol Version
		struct 
		{
			WORD MinorVer;	// KMS Protocol Minor Version
			WORD MajorVer;	// KMS Protocol Major Version
		};
	};

	BYTE Salt[16];			// KMS Client AES Initialization Vector (Salt)
	REQUEST RequestBase;	// Unhashed KMS Client Request Data
	BYTE Pad[4];			// Padding - Fill Message, so that encryptSize is divisible by blocklength
};

// KMS Server Response V5 Object
struct RESPONSE_V5
{
	union
	{
		DWORD Version;				// KMS Protocol Version
		struct 
		{
			WORD MinorVer;			// KMS Protocol Minor Version
			WORD MajorVer;			// KMS Protocol Major Version
		};
	};

	BYTE RequestSalt[16];			// KMS Client AES Initialization Vector (Salt)
	RESPONSE ResponseBase;			// Unhashed KMS Server Response Data
	BYTE Salt[16];					// KMS Server AES Initialization Vector (Salt) : Not Used. Possible MS Bug: The Request IV is used instead.
	BYTE Hash[HASH_SIZE_SHA256];	// Hash of KMS Server Response Data
	BYTE Pad[2];					// PKCS5 Padding
};

// KMS Client Request V6 Object
struct REQUEST_V6
{
	union
	{
		DWORD Version;		// KMS Protocol Version
		struct 
		{
			WORD MinorVer;	// KMS Protocol Minor Version
			WORD MajorVer;	// KMS Protocol Major Version
		};
	};

	BYTE Salt[16];			// KMS Client AES Initialization Vector (Salt)
	REQUEST RequestBase;	// Unhashed KMS Client Request Data
	BYTE Pad[4];			// Padding - Fill Message, so that encryptSize is divisible by blocklength
};

// KMS Server Response V6 Object
struct RESPONSE_V6
{
	union
	{
		DWORD Version;							// KMS Protocol Version
		struct 
		{
			WORD MinorVer;						// KMS Protocol Minor Version
			WORD MajorVer;						// KMS Protocol Major Version
		};
	};

	BYTE RequestSalt[16];						// KMS Client AES Initialization Vector (Salt)
	RESPONSE ResponseBase;						// Unhashed KMS Server Response Data
	BYTE Salt[16];								// KMS Server AES Initialization Vector (Salt) : Not Used. Possible MS Bug: The Request IV is used instead.
	BYTE Hash[HASH_SIZE_SHA256];				// Hash of KMS Server Response Data
	BYTE MachineHardwareHash[8];				// Most likely the machine hardware hash of the server
	BYTE Xor2[16];								// Xor2 ???
	BYTE HMAC_SHA256[HASH_SIZE_HMAC_SHA256];	// HMAC-SHA256 (RFC 2104)
	BYTE Pad[10];								// PKCS5 Padding
};
#pragma warning( default: 4201 )	// Enable warning C4201: nonstandard extension used : nameless struct/union
//---------------------------------------------------------------------------