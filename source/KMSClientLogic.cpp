// Includes and Namespaces
#include <regex>
#include <iostream>
#include <stdio.h>
#include <string>
#include "Crypto.h"
#include "Hash.h"
#include "KMSServer.h"
#include "KMSClientLogic.h"
#include "KMSClientSettings.h"
using namespace std;

// Link Libraries
#pragma comment(lib, "rpcrt4.lib")

// Hold KMS Client Settings
KMSClientSettings ClientSettings;

// Windows Service Parameters for Service Application
SERVICE_STATUS ClientServiceStatus; 
SERVICE_STATUS_HANDLE ClientServiceHandle;

#pragma region Application Initialization Functions
// Load Application Parameters from Command-Line
void LoadClientParameters(int argc, wchar_t *argv[], bool RunAsService)
{
	// Initialize KMS Client Settings Object
	ClientSettings.Initialize();
	ClientSettings.RunAsService = RunAsService;

	#pragma region Command-Line
	// Handle Command-Line Arguments (KMS Port or Help)
	if (argc >= 2)
	{
		if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, argv[1], -1, L"/?", -1) == CSTR_EQUAL)
		{
			printf("Usage:\n");
			printf("[KMS Port] [KMS Host] [Client Mode]\n\n");

			printf("KMS Port:\n");
			printf("\tDefaultPort:\t\tUse the built-in KMS Port.\n");
			printf("\tInteger:\t\tNumber from 1 to 65535.\n\n");

			printf("KMS Host:\n");
			printf("\tDefaultHost:\t\tUse the built-in KMS Host Address.\n");
			printf("\tString:\t\t\tA DNS Name or IP Address.\n\n");

			printf("Client Mode:\n");
			printf("\tWindows:\t\tWindows Vista Enterprise KMS (V4) Client.\n");
			printf("\tWindowsVista:\t\tWindows Vista Enterprise KMS (V4) Client.\n");
			printf("\tWindows7:\t\tWindows 7 Enterprise KMS (V4) Client.\n");
			printf("\tWindows8:\t\tWindows 8 Enterprise KMS (V5) Client.\n");
			printf("\tWindows81:\t\tWindows 8 Enterprise KMS (V6) Client.\n");
			printf("\tOffice2010:\t\tOffice 2010 Pro Plus KMS (V4) Client.\n");
			printf("\tOffice2013:\t\tOffice 2013 Pro Plus KMS (V4) Client.\n");
			printf("\tOffice2013V4:\t\tOffice 2013 Pro Plus KMS (V4) Client.\n");
			printf("\tOffice2013V5:\t\tOffice 2013 Pro Plus KMS (V5) Client.\n\n");
			printf("\tOffice2013V6:\t\tOffice 2013 Pro Plus KMS (V6) Client.\n\n");

			printf("Example:\n");
			printf("\tC:\\>\"KMS Client.exe\" 1688 127.0.0.2 Windows");
			ClientWriteLogErrorTerminate(L"\n", -1);
		}
		else
		{
			ClientValidateKMSPort(argv[1]);
		}
	}

	// Handle Command-Line Arguments (KMS Host)
	if (argc >= 3)
	{
		ClientValidateKMSHost(argv[2]);
	}

	// Handle Command-Line Arguments (Client Mode)
	if (argc >= 4)
	{
		ClientValidateKMSClientMode(argv[3]);
	}
	
	#pragma endregion
}

// Start RPC Connection and try to contact a KMS Server.
void StartKMSClient()
{
	// RPC Parameters
	RPC_STATUS status;
	RPC_WSTR pszUuid             = NULL;
	RPC_WSTR pszProtocolSequence = (RPC_WSTR)L"ncacn_ip_tcp";
	RPC_WSTR pszNetworkAddress   = (RPC_WSTR)ClientSettings.KMSHost;
	RPC_WSTR pszEndpoint         = (RPC_WSTR)ClientSettings.KMSPort;
	RPC_WSTR pszOptions          = NULL;
	RPC_WSTR pszStringBinding    = NULL;

	// Create String Binding
	status = RpcStringBindingCompose
	(
		pszUuid,
		pszProtocolSequence,
		pszNetworkAddress,
		pszEndpoint,
		pszOptions,
		&pszStringBinding
	);

	if (status)
	{
		// Format Log Message
		WCHAR Message[256];
		swprintf_s(Message, 256, L"RpcStringBindingCompose failed with code %i.\n", status);
		ClientWriteLogErrorTerminate(Message, status);
	}

	// Get RPC Binding Handle from String Binding
	status = RpcBindingFromStringBinding(pszStringBinding, &KMSServer_v1_0_c_ifspec);

	if (status)
	{
		// Format Log Message
		WCHAR Message[256];
		swprintf_s(Message, 256, L"RpcBindingFromStringBinding failed with code %i.\n", status);
		ClientWriteLogErrorTerminate(Message, status);
	}

	ClientWriteLogInformation(L"\nKMS Client Emulator started successfully.\n");

	// Send Requests
	int RequestsNeeded = ClientSettings.RequiredClientCount;
	for (int requests = 0; requests < RequestsNeeded; requests++)
	{
		// Define the size of the request
		int sizeRequest = 0;
		if (ClientSettings.KMSProtocolMajorVersion == 4)
		{
			sizeRequest = sizeof(REQUEST_V4);
		}
		else if (ClientSettings.KMSProtocolMajorVersion == 5)
		{
			sizeRequest = sizeof(REQUEST_V5);
		}		
		else
		{
			sizeRequest = sizeof(REQUEST_V6);
		}

		// Create KMS Client Request
		PBYTE request = (PBYTE)midl_user_allocate(sizeRequest);
		memcpy(request, (PBYTE)CreateRequest(), sizeRequest);

		// Send KMS Client Request to KMS Server
		status = SendRequest(request, requests, &RequestsNeeded);	
		if (status)
		{
			// Format Log Message
			WCHAR Message[256];
			swprintf_s(Message, 256, L"Activation request (KMS V%i.%i) %i of %i failed.\n", ClientSettings.KMSProtocolMajorVersion, ClientSettings.KMSProtocolMinorVersion, requests + 1, RequestsNeeded);
			ClientWriteLogErrorTerminate(Message, status);
		}
		else
		{
			// Format Log Message
			WCHAR Message[256];
			swprintf_s(Message, 256, L"Activation request (KMS V%i.%i) %i of %i sent.\n", ClientSettings.KMSProtocolMajorVersion, ClientSettings.KMSProtocolMinorVersion, requests + 1, RequestsNeeded);
			ClientWriteLogInformation(Message);
		}
	}

	// Free String Binding
	status = RpcStringFree(&pszStringBinding); 

	if (status)
	{
		// Format Log Message
		WCHAR Message[256];
		swprintf_s(Message, 256, L"RpcStringFree failed with code %i.\n", status);
		ClientWriteLogErrorTerminate(Message, status);
	}

	// Free RPC Binding
	status = RpcBindingFree(&KMSServer_v1_0_c_ifspec);

	if (status)
	{
		// Format Log Message
		WCHAR Message[256];
		swprintf_s(Message, 256, L"RpcBindingFree failed with code %i.\n", status);
		ClientWriteLogErrorTerminate(Message, status);
	}
}
#pragma endregion

#pragma region KMS Client Request Generation Functions
// Create KMS Client Request Data Based on KMS Client Protocol Version.
PBYTE CreateRequest()
{
	// KMS Protocol Major Version
	if (ClientSettings.KMSProtocolMajorVersion == 4)
	{
		return CreateRequestV4();
	}
	else if (ClientSettings.KMSProtocolMajorVersion == 5)
	{
		return CreateRequestV5();
	}
	else
	{
		return CreateRequestV6();
	}
}

// Create Base KMS Client Request Object.
void CreateRequestBase(REQUEST* const Request)
{
	// KMS Protocol Version 
	Request->MajorVer = ClientSettings.KMSProtocolMajorVersion;
	Request->MinorVer = ClientSettings.KMSProtocolMinorVersion;

	// KMS Client is NOT a VM
	Request->IsClientVM = 0;

	// License Status
	Request->LicenseStatus = ClientSettings.KMSClientLicenseStatus;

	// Grace Time
	Request->GraceTime = 43200;

	// Application ID
	UuidFromStringW((RPC_WSTR)ClientSettings.KMSClientAppID, &Request->ApplicationId);

	// SKU ID
	UuidFromStringW((RPC_WSTR)ClientSettings.KMSClientSkuID, &Request->SkuId);

	// KMS Counted ID
	UuidFromStringW((RPC_WSTR)ClientSettings.KMSClientKMSCountedID, &Request->KmsCountedId);

	// CMID
	CoCreateGuid(&Request->ClientMachineId);

	// Minimum Clients
	Request->RequiredClientCount = ClientSettings.RequiredClientCount;

	// Timestamp
	GetSystemTimeAsFileTime(&Request->RequestTime);

	// Machine Name
	static const char alphanum[] = "0123456789" "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz";

	// Seed Random Number Generator
	srand(GetTickCount());

	// Generate Random Machine Name (Up to 63 Characters)
	int MachineNameLength = rand() % 63 + 1;
	for (int i = 0; i < MachineNameLength; i++)
	{
		Request->MachineName[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}
	Request->MachineName[MachineNameLength] = 0;
}

// Create Hashed KMS Client Request Data for KMS Protocol Version 4.
PBYTE CreateRequestV4()
{
	// Allocate KMS Client Request Buffer
	PBYTE request = (PBYTE)midl_user_allocate(sizeof(REQUEST_V4));

	// Clean buffer memory
	memset(request, 0x00, sizeof(REQUEST_V4));

	// Create KMS Client Request Base
	CreateRequestBase((REQUEST*)request);

    // Create Hash
    GetHash(sizeof(REQUEST), request, request + sizeof(REQUEST));

    // Return Request
	return request;
}

// Create Encrypted KMS Client Request Data for KMS Protocol Version 5.
PBYTE CreateRequestV5()
{
	// Allocate KMS Client Request Buffer
	PBYTE request = (PBYTE)midl_user_allocate(sizeof(REQUEST_V5));

	// Clean buffer memory
	memset(request, 0x00, sizeof(REQUEST_V5));

	// Temporary Pointer for access to REQUEST_V5 structure
	REQUEST_V5 *requestptr = (REQUEST_V5 *)request;

	// KMS Protocol Version
	requestptr->MajorVer = ClientSettings.KMSProtocolMajorVersion;
	requestptr->MinorVer = ClientSettings.KMSProtocolMinorVersion;

	// Seed Random Number Generator
	srand(GetTickCount());

	// Generate a Random Salt Key
	for(int i = 0; i < 16; i++)
	{
		requestptr->Salt[i] = rand() % 256;
	}

	// Set KMS Client Request Base
	CreateRequestBase(&requestptr->RequestBase);

	// Encrypted Size
	DWORD EncryptedSize = sizeof(requestptr->RequestBase);

	// AES-128 Encrypt
	AESEncryptMessage(requestptr->Salt, (PBYTE)(&requestptr->RequestBase), &EncryptedSize, sizeof(requestptr->RequestBase) + sizeof(requestptr->Pad));

    // Return Request
    return request;
}

// Create Encrypted KMS Client Request Data for KMS Protocol Version 6.
PBYTE CreateRequestV6()
{
	// V6: AES key
	BYTE AES_V6_KEY[16] = {0xA9, 0x4A, 0x41, 0x95, 0xE2, 0x01, 0x43, 0x2D, 0x9B, 0xCB, 0x46, 0x04, 0x05, 0xD8, 0x4A, 0x21};

	// Allocate KMS Client Request Buffer
	PBYTE request = (PBYTE)midl_user_allocate(sizeof(REQUEST_V6));

	// Clean buffer memory
	memset(request, 0x00, sizeof(REQUEST_V6));

	// Temporary Pointer for access to REQUEST_V6 structure
	REQUEST_V6 *requestptr = (REQUEST_V6 *)request;

	// KMS Protocol Version
	requestptr->MajorVer = ClientSettings.KMSProtocolMajorVersion;
	requestptr->MinorVer = ClientSettings.KMSProtocolMinorVersion;

	// Seed Random Number Generator
	srand(GetTickCount());

	// Generate a Random Salt Key
	for(int i = 0; i < 16; i++)
	{
		requestptr->Salt[i] = rand() % 256;
	}

	// Set KMS Client Request Base
	CreateRequestBase(&requestptr->RequestBase);

	// Set Padding to 0x04
	memset(&requestptr->Pad, 0x04, sizeof(&requestptr->Pad));

	// Encrypted Size
	DWORD EncryptedSize = sizeof(requestptr->RequestBase) + sizeof(requestptr->Pad);

	AesInit(AES_TYPE_128, AES_MODE_CBC, 0x04, AES_V6_KEY, requestptr->Salt);
	EncryptMessage(EncryptedSize, (PBYTE)(&requestptr->RequestBase));
	AesClear();

    // Return Request
    return request;
}

// Read KMS Server Response V4 from Byte Array
void ReadResponseV4(RESPONSE_V4& Response_v4, int responseSize, PBYTE response)
{
	int copySize =
		sizeof(Response_v4.ResponseBase.Version) +
		sizeof(Response_v4.ResponseBase.KMSPIDLength) +
		(((RESPONSE_V4*)response)->ResponseBase.KMSPIDLength <= PID_BUFFER_SIZE << 1 ?
		((RESPONSE_V4*)response)->ResponseBase.KMSPIDLength :
		PID_BUFFER_SIZE << 1);

	memcpy(&Response_v4, response, copySize);
	memcpy(&Response_v4.ResponseBase.ClientMachineId, response + copySize, responseSize - copySize);

	// Ensure KMSPID is NULL Terminated
	Response_v4.ResponseBase.KMSPID[PID_BUFFER_SIZE - 1] = 0;
}

// Read KMS Server Response V5 from Byte Array
void ReadResponseV5(RESPONSE_V5& Response_v5, int responseSize, PBYTE response)
{
	// Get Size of the First Part of the Response
	int copySize1 =
		sizeof(Response_v5.Version) +
		sizeof(Response_v5.RequestSalt);

	// Decrypt KMS Server Response (Encrypted part starts after RequestSalt)
	responseSize -= copySize1;
	AESDecryptMessage(((RESPONSE_V5*)(response))->RequestSalt, response + copySize1, (DWORD*)&responseSize);

	// Add Size of KMS Protocol Version, KMS PID Length and KMS PID (Variable Sized)
	copySize1 +=
		sizeof(Response_v5.ResponseBase.Version) +
		sizeof(Response_v5.ResponseBase.KMSPIDLength) +
		(((RESPONSE_V5*)response)->ResponseBase.KMSPIDLength <= PID_BUFFER_SIZE << 1 ?
		((RESPONSE_V5*)response)->ResponseBase.KMSPIDLength :
		PID_BUFFER_SIZE << 1);

	// Copy Part 1 of Response up to KMS PID (Variable Sized)
	memcpy(&Response_v5, response, copySize1);

	// Ensure KMSPID is NULL Terminated
	Response_v5.ResponseBase.KMSPID[PID_BUFFER_SIZE - 1] = 0;

	// Get Size of the Second Part of the Response
	int copySize2 =
		sizeof(Response_v5.ResponseBase.ClientMachineId) +
		sizeof(Response_v5.ResponseBase.RequestTime) +
		sizeof(Response_v5.ResponseBase.KMSCurrentCount) +
		sizeof(Response_v5.ResponseBase.VLActivationInterval) +
		sizeof(Response_v5.ResponseBase.VLRenewalInterval) +
		sizeof(Response_v5.Salt) +
		sizeof(Response_v5.Hash);

	// Copy Part 2 of Response
	memcpy(&Response_v5.ResponseBase.ClientMachineId, response + copySize1, copySize2);
}

// Read KMS Server Response V6 from Byte Array
void ReadResponseV6(RESPONSE_V6& Response_v6, int responseSize, PBYTE response)
{
	// V6: AES key
	BYTE AES_V6_KEY[16] = {0xA9, 0x4A, 0x41, 0x95, 0xE2, 0x01, 0x43, 0x2D, 0x9B, 0xCB, 0x46, 0x04, 0x05, 0xD8, 0x4A, 0x21};

	// Get Size of the First Part of the Response
	int copySize =
		sizeof(Response_v6.Version) +
		sizeof(Response_v6.RequestSalt);

	// Read the first part.
	memcpy(&Response_v6, response, copySize);
	response += copySize;
	responseSize -= copySize;

	// Decrypt the response.
	AesInit(AES_TYPE_128, AES_MODE_CBC, 0x04, AES_V6_KEY, Response_v6.RequestSalt);
	DecryptMessage(responseSize, response);
	AesClear();

	// Read version.
	copySize = sizeof(Response_v6.ResponseBase.Version);
	memcpy(&Response_v6.ResponseBase.Version, response, copySize);
	response += copySize;
	responseSize -= copySize;

	// Read KMS PID length.
	copySize = sizeof(Response_v6.ResponseBase.KMSPIDLength);
	memcpy(&Response_v6.ResponseBase.KMSPIDLength, response, copySize);
	response += copySize;
	responseSize -= copySize;

	// Read KMS PID.
	copySize = Response_v6.ResponseBase.KMSPIDLength <= PID_BUFFER_SIZE << 1 ? Response_v6.ResponseBase.KMSPIDLength : PID_BUFFER_SIZE << 1;
	memcpy(&Response_v6.ResponseBase.KMSPID, response, copySize);
	response += copySize;
	responseSize -= copySize;

	// Ensure KMSPID is NULL Terminated
	Response_v6.ResponseBase.KMSPID[PID_BUFFER_SIZE - 1] = 0;

	// Read the rest into the structure.
	memcpy(&Response_v6.ResponseBase.ClientMachineId, response, responseSize);
}

// Function to Send Request to KMS Server
// Used to allow use of RpcTryExcept
int SendRequest(PBYTE request, const int requestsSent,  int* const requestsNeeded)
{
	RpcTryExcept  
	{
		// Allocate Memory for Response
		int responseSize = MAX_RESPONSE_SIZE;
		PBYTE resp = (PBYTE)midl_user_allocate(MAX_RESPONSE_SIZE);

		if (ClientSettings.KMSProtocolMajorVersion == 4)
		{
			// Call KMS Server via RPC for V4
			ActivationRequest(KMSServer_v1_0_c_ifspec, sizeof(REQUEST_V4), request, &responseSize, &resp);
		}
		else if (ClientSettings.KMSProtocolMajorVersion == 5)
		{
			// Call KMS Server via RPC for V5
			ActivationRequest(KMSServer_v1_0_c_ifspec, sizeof(REQUEST_V5), request, &responseSize, &resp);
		}
		else
		{
			// Call KMS Server via RPC for V6
			ActivationRequest(KMSServer_v1_0_c_ifspec, sizeof(REQUEST_V6), request, &responseSize, &resp);
		}

		// Verify Response Was Received
		if (resp == NULL)
		{
			ClientWriteLogErrorTerminate(L"Failed to get Activation response.\n", -1);
		}

		// Determine how many more requests are needed.
		if (requestsSent < 1)
		{
			// Place to Store Base Response Data
			RESPONSE response;

			// KMSPID from Response
		    WCHAR* KMSPID = L"";

			// KMSHWID from Response
			WCHAR KMSHWID[256];

			// ActivatedMachines from Response
			DWORD ActivatedMachines;

			if (ClientSettings.KMSProtocolMajorVersion == 4)
			{
				// Get KMS Server Response Object
				RESPONSE_V4 response_v4;
				ReadResponseV4(response_v4, responseSize, resp);

				// Get Base KMS Server Response Object
				response = response_v4.ResponseBase;

				// Read KMSPID from Response
				KMSPID = response.KMSPID;

				// Read ActivatedMachines from Response
				ActivatedMachines = response.KMSCurrentCount;
			}
			else if (ClientSettings.KMSProtocolMajorVersion == 5)
			{
				// Get KMS Server Response Object
				RESPONSE_V5 response_v5;
				ReadResponseV5(response_v5, responseSize, resp);

				// Get Base KMS Server Response Object
				response = response_v5.ResponseBase;

				// Read KMSPID from Response
				KMSPID = response.KMSPID;

				// Read ActivatedMachines from Response
				ActivatedMachines = response.KMSCurrentCount;
			}
			else
			{
				// Get KMS Server Response Object
				RESPONSE_V6 response_v6;
				ReadResponseV6(response_v6, responseSize, resp);

				// Get Base KMS Server Response Object
				response = response_v6.ResponseBase;

				// Read KMSPID from Response
				KMSPID = response.KMSPID;

				// Read KMSHWID from Response
				swprintf_s(KMSHWID, 256, L"%02X%02X%02X%02X%02X%02X%02X%02X", response_v6.MachineHardwareHash[7], response_v6.MachineHardwareHash[6], response_v6.MachineHardwareHash[5], response_v6.MachineHardwareHash[4], response_v6.MachineHardwareHash[3], response_v6.MachineHardwareHash[2], response_v6.MachineHardwareHash[1], response_v6.MachineHardwareHash[0]);

				// Read ActivatedMachines from Response
				ActivatedMachines = response.KMSCurrentCount;
			}

			ClientWriteLogInformation(L"Successfully received response from KMS Server.\n");

			// Format Log Message
			WCHAR Message[256];
			swprintf_s(Message, 256, L"KMS Server PID: %s.\n", KMSPID);
			ClientWriteLogInformation(Message);
			if (ClientSettings.KMSProtocolMajorVersion > 5)
			{
				swprintf_s(Message, 256, L"KMS Server HWID: %s.\n", KMSHWID);
				ClientWriteLogInformation(Message);
			}

			// Send no more requests if the client count was sufficient.
			if (ActivatedMachines >= ClientSettings.RequiredClientCount)
			{
				*requestsNeeded = 1;
			}
			// Send as many requests as needed.
			else
			{
				*requestsNeeded = (ClientSettings.RequiredClientCount - ActivatedMachines) + 1;
			}
		}
		return 0;
	}
	RpcExcept(1) 
	{
		// Get RPC Exception Code
		unsigned long ulCode = RpcExceptionCode();
			
		// Format Log Message
		WCHAR Message[256];
		swprintf_s(Message, 256, L"Runtime reported exception 0x%lx = %ld\n", ulCode, ulCode);
		ClientWriteLogErrorTerminate(Message, ulCode);

		// Return
		return false;
	}
	RpcEndExcept
}
#pragma endregion

#pragma region Parameter Validation Functions
// Validate KMS Port Parameter
void ClientValidateKMSPort(WCHAR* KMSPort)
{
	// Check if the KMS Port is not the Default
	if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, KMSPort, -1, L"DefaultPort", -1) != CSTR_EQUAL)
	{
		// Check if KMS Port is Valid Number
		if (regex_match(KMSPort, wregex(L"^([0-9]+)$")))
		{
			// Check if KMS Port is Valid Range
			if(_wtoi(KMSPort) < 1 || _wtoi(KMSPort) > 65535)
			{
				// Format Log Message
				WCHAR Message[256];
				swprintf_s(Message, 256, L"Invalid KMS Port Range! %s is not a valid argument.\n", KMSPort);
				ClientWriteLogErrorTerminate(Message, -1);
			}
			else
			{
				// Apply Setting
				StringCchCopyW(ClientSettings.KMSPort, PORT_BUFFER_SIZE, KMSPort);

				// Format Log Message
				WCHAR Message[256];
				swprintf_s(Message, 256, L"KMS Port: %s \n", KMSPort);
				ClientWriteLogInformation(Message);
			}
		}
		else			
		{
			// Format Log Message
			WCHAR Message[256];
			swprintf_s(Message, 256, L"Invalid KMS Port! %s is not a valid argument.\n", KMSPort);
			ClientWriteLogErrorTerminate(Message, -1);
		}
	}
}

// Validate KMS Host Parameter
void ClientValidateKMSHost(WCHAR* KMSHost)
{
	// Check if the KMS PID is not the Default
	if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, KMSHost, -1, L"DefaultHost", -1) != CSTR_EQUAL)
	{
		// Apply Setting
		StringCchCopyW(ClientSettings.KMSHost, 256, KMSHost);

		// Format Log Message
		WCHAR Message[256];
		swprintf_s(Message, 256, L"KMS Host: %s \n", KMSHost);
		ClientWriteLogInformation(Message);
	}
}

// Validate KMS Client Mode
void ClientValidateKMSClientMode(WCHAR* KMSClientMode)
{
	// Check if KMS Client Mode is Valid
	if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, KMSClientMode, -1, L"Windows", -1) == CSTR_EQUAL || CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, KMSClientMode, -1, L"WindowsVista", -1) == CSTR_EQUAL)
	{
		ClientSettings.RequiredClientCount = 25;
		ClientSettings.KMSProtocolMajorVersion = 4;
		StringCchCopyW(ClientSettings.KMSClientAppID, GUID_BUFFER_SIZE, L"55c92734-d682-4d71-983e-d6ec3f16059f");
		StringCchCopyW(ClientSettings.KMSClientSkuID, GUID_BUFFER_SIZE, L"cfd8ff08-c0d7-452b-9f60-ef5c70c32094");
		StringCchCopyW(ClientSettings.KMSClientKMSCountedID, GUID_BUFFER_SIZE, L"212a64dc-43b1-4d3d-a30c-2fc69d2095c6");
	}
	else if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, KMSClientMode, -1, L"Windows7", -1) == CSTR_EQUAL)
	{
		ClientSettings.RequiredClientCount = 25;
		ClientSettings.KMSProtocolMajorVersion = 4;
		StringCchCopyW(ClientSettings.KMSClientAppID, GUID_BUFFER_SIZE, L"55c92734-d682-4d71-983e-d6ec3f16059f");
		StringCchCopyW(ClientSettings.KMSClientSkuID, GUID_BUFFER_SIZE, L"ae2ee509-1b34-41c0-acb7-6d4650168915");
		StringCchCopyW(ClientSettings.KMSClientKMSCountedID, GUID_BUFFER_SIZE, L"7fde5219-fbfa-484a-82c9-34d1ad53e856");
	}
	else if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, KMSClientMode, -1, L"Windows8", -1) == CSTR_EQUAL)
	{
		ClientSettings.RequiredClientCount = 25;
		ClientSettings.KMSProtocolMajorVersion = 5;
		StringCchCopyW(ClientSettings.KMSClientAppID, GUID_BUFFER_SIZE, L"55c92734-d682-4d71-983e-d6ec3f16059f");
		StringCchCopyW(ClientSettings.KMSClientSkuID, GUID_BUFFER_SIZE, L"458e1bec-837a-45f6-b9d5-925ed5d299de");
		StringCchCopyW(ClientSettings.KMSClientKMSCountedID, GUID_BUFFER_SIZE, L"3c40b358-5948-45af-923b-53d21fcc7e79");
	}
	else if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, KMSClientMode, -1, L"Windows81", -1) == CSTR_EQUAL)
	{
		ClientSettings.RequiredClientCount = 25;
		ClientSettings.KMSProtocolMajorVersion = 6;
		StringCchCopyW(ClientSettings.KMSClientAppID, GUID_BUFFER_SIZE, L"55c92734-d682-4d71-983e-d6ec3f16059f");
		StringCchCopyW(ClientSettings.KMSClientSkuID, GUID_BUFFER_SIZE, L"81671aaf-79d1-4eb1-b004-8cbbe173afea");
		StringCchCopyW(ClientSettings.KMSClientKMSCountedID, GUID_BUFFER_SIZE, L"cb8fc780-2c05-495a-9710-85afffc904d7");
	}
	else if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, KMSClientMode, -1, L"Office2010", -1) == CSTR_EQUAL)
	{
		ClientSettings.RequiredClientCount = 5;
		ClientSettings.KMSProtocolMajorVersion = 4;
		StringCchCopyW(ClientSettings.KMSClientAppID, GUID_BUFFER_SIZE, L"59a52881-a989-479d-af46-f275c6370663");
		StringCchCopyW(ClientSettings.KMSClientSkuID, GUID_BUFFER_SIZE, L"6f327760-8c5c-417c-9b61-836a98287e0c");
		StringCchCopyW(ClientSettings.KMSClientKMSCountedID, GUID_BUFFER_SIZE, L"e85af946-2e25-47b7-83e1-bebcebeac611");
	}
	else if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, KMSClientMode, -1, L"Office2013", -1) == CSTR_EQUAL ||
		     CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, KMSClientMode, -1, L"Office2013V4", -1) == CSTR_EQUAL)
	{
		ClientSettings.RequiredClientCount = 5;
		ClientSettings.KMSProtocolMajorVersion = 4;
		StringCchCopyW(ClientSettings.KMSClientAppID, GUID_BUFFER_SIZE, L"0ff1ce15-a989-479d-af46-f275c6370663");
		StringCchCopyW(ClientSettings.KMSClientSkuID, GUID_BUFFER_SIZE, L"b322da9c-a2e2-4058-9e4e-f59a6970bd69");
		StringCchCopyW(ClientSettings.KMSClientKMSCountedID, GUID_BUFFER_SIZE, L"e6a6f1bf-9d40-40c3-aa9f-c77ba21578c0");
	}
	else if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, KMSClientMode, -1, L"Office2013V5", -1) == CSTR_EQUAL)
	{
		ClientSettings.RequiredClientCount = 5;
		ClientSettings.KMSProtocolMajorVersion = 5;
		StringCchCopyW(ClientSettings.KMSClientAppID, GUID_BUFFER_SIZE, L"0ff1ce15-a989-479d-af46-f275c6370663");
		StringCchCopyW(ClientSettings.KMSClientSkuID, GUID_BUFFER_SIZE, L"b322da9c-a2e2-4058-9e4e-f59a6970bd69");
		StringCchCopyW(ClientSettings.KMSClientKMSCountedID, GUID_BUFFER_SIZE, L"e6a6f1bf-9d40-40c3-aa9f-c77ba21578c0");
	}
	else if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, KMSClientMode, -1, L"Office2013V6", -1) == CSTR_EQUAL)
	{
		ClientSettings.RequiredClientCount = 5;
		ClientSettings.KMSProtocolMajorVersion = 6;
		StringCchCopyW(ClientSettings.KMSClientAppID, GUID_BUFFER_SIZE, L"0ff1ce15-a989-479d-af46-f275c6370663");
		StringCchCopyW(ClientSettings.KMSClientSkuID, GUID_BUFFER_SIZE, L"b322da9c-a2e2-4058-9e4e-f59a6970bd69");
		StringCchCopyW(ClientSettings.KMSClientKMSCountedID, GUID_BUFFER_SIZE, L"e6a6f1bf-9d40-40c3-aa9f-c77ba21578c0");
	}
	else
	{
		// Format Log Message
		WCHAR Message[256];
		swprintf_s(Message, 256, L"Invalid KMS Client Type! %s is not a valid argument.\n", KMSClientMode);
		ClientWriteLogErrorTerminate(Message, -1);
	}
	
	// Apply Setting
	StringCchCopyW(ClientSettings.KMSClientMode, 256, KMSClientMode);

	// Format Log Message
	WCHAR Message[256];
	swprintf_s(Message, 256, L"KMS Client Mode: %s \n", KMSClientMode);
	ClientWriteLogInformation(Message);
}
#pragma endregion

#pragma region Logging Functions
// Log an informational message to the Console or Windows Application Event Log.
void ClientWriteLogInformation(WCHAR* const Message)
{
	// Log Message Buffer
	WCHAR logMessage[256];

	// Write Log Message to Buffer
	StringCbPrintfW(logMessage, 256, Message);

	// Choose Log Source
	if (ClientSettings.RunAsService)
	{
		// Output to Windows Event Log: Qualifiers: 16384, EventId: 12290
		ClientWriteEventLogEntry(0x40003002, logMessage, EVENTLOG_INFORMATION_TYPE);
	}
	else
	{
		// Output to Console
		wprintf(L"%s", logMessage);
	}
}

// Log an error message to the Console or Windows Application Event Log.
void ClientWriteLogError(WCHAR* const Message)
{
	// Log Message Buffer
	WCHAR logMessage[256];

	// Write Log Message to Buffer
	StringCbPrintfW(logMessage, 256, Message);

	// Choose Log Source
	if (ClientSettings.RunAsService)
	{
		// Output to Windows Event Log: Qualifiers: 16384, EventId: 902
		ClientWriteEventLogEntry(0x40000386, logMessage, EVENTLOG_ERROR_TYPE);
	}
	else
	{
		// Output to Console
		wprintf(L"%s", logMessage);
	}
}

// Log an error message to the Console or Windows Application Event Log and terminate program.
void ClientWriteLogErrorTerminate(WCHAR* const Message, int ExitCode)
{
	// Call ClientWriteLogError
	ClientWriteLogError(Message);

	if (!ClientSettings.RunAsService)
	{
		// Exit Program
		exit(ExitCode);
	}
	else
	{
		// Exit Service
		ClientServiceStatus.dwCurrentState       = SERVICE_STOPPED; 
		ClientServiceStatus.dwWin32ExitCode      = ExitCode; 
		SetServiceStatus(ClientServiceHandle, &ClientServiceStatus); 
	}
}

// Log a message to the Windows Application Event Log.
void ClientWriteEventLogEntry(DWORD dwIdentifier, WCHAR* const lpszMessage, WORD wType)
{
	HANDLE hEventSource = OpenEventLogW(NULL, L"KmsRequests"); // Provider: KmsRequests or Microsoft-Windows-Security-SPP

	if(hEventSource != NULL)
	{
		ReportEventW(
			hEventSource,			// Event log handle
			wType,					// Event type
			NULL,					// Event category
			dwIdentifier,			// Event identifier
			NULL,					// No security identifier
			1,						// Size of lpszStrings array
			NULL,					// No binary data
			(LPCWSTR*)&lpszMessage,	// Array of strings
			NULL					// No binary data
		);

		CloseEventLog(hEventSource);
	}
}
#pragma endregion