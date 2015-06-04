// Includes and Namespaces
#include <regex>
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <string>
#include "Crypto.h"
#include "Hash.h"
#include "KMSPID.h"
#include "KMSHWID.h"
#include "KMSServer.h"
#include "KMSServerLogic.h"
#include "KMSServerSettings.h"
using namespace std;

// Link Libraries
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// Hold KMS Server Settings
KMSServerSettings ServerSettings;

// Windows Service Parameters for Service Application
SERVICE_STATUS ServerServiceStatus; 
SERVICE_STATUS_HANDLE ServerServiceHandle;

// Defined in Hash.cpp
extern HMAC_KEYBLOB Hmac_keyblob;

#pragma region Application Initialization Functions
// Load Application Parameters from Command-Line or Registry.
void LoadServerParameters(int argc, wchar_t* argv[], bool RunAsService)
{
	// Initialize KMS Server Settings Object
	ServerSettings.Initialize();
	ServerSettings.RunAsService = RunAsService;

	if (!RunAsService)
	{
		#pragma region Command-Line
		// Handle Command-Line Arguments (KMS Port or Help)
		if (argc >= 2)
		{
			if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, argv[1], -1, L"/?", -1) == CSTR_EQUAL)
			{
				printf("Usage:\n");
				printf("[KMS Port] [KMS PID] [KMS HWID] [Activation Interval] [Renewal Interval] [Kill Processes]\n\n");

				printf("KMS Port:\n");
				printf("\tDefaultPort:\t\tUse the built-in KMS Port.\n");
				printf("\tInteger:\t\tNumber from 1 to 65535.\n\n");

				printf("KMS PID:\n");
				printf("\tRandomKMSPID:\t\tGenerate a random KMS PID.\n");
				printf("\tString:\t\t\tA Microsoft Extended Product Key ID.\n\n");

				printf("KMS HWID:\n");
				printf("\tDefaultKMSHWID:\t\tUse the built-in KMS HWID.\n");
				printf("\tString:\t\t\t16 Hex character KMS HWID (No 0x).\n\n");

				printf("Activation Interval:\n");
				printf("\tDefaultAI:\t\tUse the built-in Activation Interval.\n");
				printf("\tInteger:\t\tNumber (in minutes) from 15 to 43200.\n\n");

				printf("Renewal Interval:\n");
				printf("\tDefaultRI:\t\tUse the built-in Renewal Interval.\n");
				printf("\tInteger:\t\tNumber (in minutes) from 15 to 43200.\n\n");

				printf("Kill Processes:\n");
				printf("\tKillProcessOnPort:\tForce open the KMS Port if this is present.\n\n");

				printf("Example:\n");
				printf("\tC:\\>\"KMS Server.exe\" 1688 RandomKMSPID DefaultKMSHWID 43200 43200 KillProcessOnPort");
				ServerWriteLogErrorTerminate(L"\n", -1);
			}
			else
			{
				ServerValidateKMSPort(argv[1]);
			}
		}

		// Handle Command-Line Arguments (KMS PID)
		if (argc >= 3)
		{
			ServerValidateKMSPID(argv[2]);
		}

		// Handle Command-Line Arguments (KMS HWID)
		if (argc >= 4)
		{
			ServerValidateKMSHWID(argv[3]);
		}

		// Handle Command-Line Arguments (Activation Interval)
		if (argc >= 5)
		{
			if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, argv[4], -1, L"DefaultAI", -1) != CSTR_EQUAL)
			{
				// Check if Activation Interval is Valid Number
				if (regex_match(argv[4], wregex(L"^([0-9]+)$")))
				{
					ServerValidateVLActivationInterval(_wtoi(argv[4]));
				}
				else
				{
					// Format Log Message
					WCHAR Message[256];
					swprintf_s(Message, 256, L"Invalid KMS Activation Interval! %s is not a valid argument.\n", argv[4]);
					ServerWriteLogErrorTerminate(Message, -1);
				}
			}
		}
	
		// Handle Command-Line Arguments (Renewal Interval)
		if (argc >= 6)
		{
			if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, argv[5], -1, L"DefaultRI", -1) != CSTR_EQUAL)
			{
				// Check if Renewal Interval is Valid Number
				if (regex_match(argv[5], wregex(L"^([0-9]+)$")))
				{
					ServerValidateVLRenewalInterval(_wtoi(argv[5]));
				}
				else
				{
					// Format Log Message
					WCHAR Message[256];
					swprintf_s(Message, 256, L"Invalid KMS Renewal Interval! %s is not a valid argument.\n", argv[5]);
					ServerWriteLogErrorTerminate(Message, -1);
				}
			}
		}

		// Handle Command-Line Arguments (Free TCP/IP)
		if (argc >= 7)
		{
			if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, argv[6], -1, L"KillProcessOnPort", -1) == CSTR_EQUAL)
			{
				// Apply Setting
				ServerSettings.KillProcesses = true;
				ServerWriteLogInformation(L"KMS Port Process Termination: Enabled \n");
			}
			else
			{
				// Apply Setting
				ServerSettings.KillProcesses = false;
				ServerWriteLogInformation(L"KMS Port Process Termination: Disabled \n");
			}
		}
		#pragma endregion
	}
	else
	{
		#pragma region Registry
		// Create Buffers for Values
		WCHAR KMSPID[256] = {0};
		WCHAR KMSHWID[256] = {0};
		WCHAR KMSPort[256] = {0};
		DWORD VLActivationInterval = 0;
		DWORD VLRenewalInterval = 0;
		DWORD KillProcesses = 0;

		// Open Registry Key
		HKEY hKey;
		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\KMSServerService\\Parameters", NULL, KEY_READ, &hKey) == ERROR_SUCCESS)
		{
			// Buffer Size
			DWORD bufferSize = 0;

			// Handle Registry Parameters (KMS PID)
			bufferSize = 256;
			RegQueryValueExW(hKey, L"KMSPID", NULL, NULL, (LPBYTE)KMSPID, &bufferSize);

			// Handle Registry Parameters (KMS HWID)
			bufferSize = 256;
			RegQueryValueExW(hKey, L"KMSHWID", NULL, NULL, (LPBYTE)KMSHWID, &bufferSize);

			// Handle Registry Parameters (KMS Port)
			bufferSize = 256;
			RegQueryValueExW(hKey, L"KMSPort", NULL, NULL, (LPBYTE)KMSPort, &bufferSize);

			// Handle Registry Parameters (Activation Interval)
			bufferSize = sizeof(DWORD);
			RegQueryValueExW(hKey, L"VLActivationInterval", NULL, NULL, (LPBYTE)&VLActivationInterval, &bufferSize);

			// Handle Registry Parameters (Renewal Interval)
			bufferSize = sizeof(DWORD);
			RegQueryValueExW(hKey, L"VLRenewalInterval", NULL, NULL, (LPBYTE)&VLRenewalInterval, &bufferSize);

			// Handle Registry Parameters (Free TCP/IP)
			bufferSize = sizeof(DWORD);
			RegQueryValueExW(hKey, L"KillProcessOnPort", NULL, NULL, (LPBYTE)&KillProcesses, &bufferSize);
		
			// Close Registry Key
			RegCloseKey(hKey);
		}

		// Validate Values
		ServerValidateKMSPort(KMSPort);
		ServerValidateKMSPID(KMSPID);
		ServerValidateKMSHWID(KMSHWID);
		ServerValidateVLActivationInterval(VLActivationInterval);
		ServerValidateVLRenewalInterval(VLRenewalInterval);

		// Handle External Process Termination
		if (KillProcesses > 0)
		{
			// Apply Setting
			ServerSettings.KillProcesses = true;
			ServerWriteLogInformation(L"KMS Port Process Termination: Enabled \n");
		}
		else
		{
			// Apply Setting
			ServerSettings.KillProcesses = false;
			ServerWriteLogInformation(L"KMS Port Process Termination: Disabled \n");
		}

		#pragma endregion
	}
}

// Start RPC Connection and listen indefinitely for KMS Clients.
void StartKMSServer()
{
	// Uses the protocol combined with the endpoint for receiving remote procedure calls.
    RPC_STATUS status = RpcServerUseProtseqEp
	(
		// Use TCP/IP protocol.
		(RPC_WSTR)L"ncacn_ip_tcp",  
		// Backlog queue length for TCP/IP.
		RPC_C_PROTSEQ_MAX_REQS_DEFAULT, 
		// TCP/IP port to use.
		(RPC_WSTR)ServerSettings.KMSPort, 
		// No security.
		NULL
	); 
	
	if (status)
	{
		// TCP/IP Port in Use
		if (status == RPC_S_DUPLICATE_ENDPOINT && ServerSettings.KillProcesses)
		{
			// TCP Table and TCP Table Size
			MIB_TCPTABLE_OWNER_PID *pTCPInfo;
		    DWORD dwSize = 0;

			// Get TCP Table Size
			GetExtendedTcpTable(NULL, &dwSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

			// Allocate Memory for TCP Table
			pTCPInfo = (MIB_TCPTABLE_OWNER_PID*)malloc(dwSize);			
			
			// Get TCP Table Data
			GetExtendedTcpTable(pTCPInfo, &dwSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

			// Read TCP Table Data
			for (DWORD i = 0; i < pTCPInfo->dwNumEntries; i++)
			{
				// Get Process ID, Opened Port of the Process and KMS Port
				DWORD processID = pTCPInfo->table[i].dwOwningPid;
				DWORD kmsport = _wtoi(ServerSettings.KMSPort);
				DWORD port = ntohs((u_short)pTCPInfo->table[i].dwLocalPort);

				// Check if this Process has the KMS Port
				if (port == kmsport)
				{

					// Enable Debug Privileges
					HANDLE tokenHandle; 
					OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle); 
					TOKEN_PRIVILEGES privilegeToken; 
					LookupPrivilegeValue(0, SE_DEBUG_NAME, &privilegeToken.Privileges[0].Luid); 
					privilegeToken.PrivilegeCount = 1; 
					privilegeToken.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
					AdjustTokenPrivileges(tokenHandle, 0, &privilegeToken, sizeof(TOKEN_PRIVILEGES), 0, 0); 
					CloseHandle(tokenHandle); 

					// Kill Process using the KMS Port
					HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processID);
					if (hProcess != NULL)
					{
						TerminateProcess(hProcess, 0);			
						CloseHandle(hProcess);
					}
					else
					{
						// Format Log Message
						WCHAR Message[256];
						swprintf_s(Message, 256, L"Failed to get handle to kill Process ID: %i.\n", processID);
						ServerWriteLogErrorTerminate(Message, -1);
					}
					break;
				}
			}
			
			// Connect on Port Again
			Sleep(5000);
			status = RpcServerUseProtseqEp
			(
				// Use TCP/IP protocol.
				(RPC_WSTR)L"ncacn_ip_tcp",  
				// Backlog queue length for TCP/IP.
				RPC_C_PROTSEQ_MAX_REQS_DEFAULT, 
				// TCP/IP port to use.
				(RPC_WSTR)ServerSettings.KMSPort, 
				// No security.
				NULL
			); 
		}
		else
		{
			// Format Log Message
			WCHAR Message[256];
			swprintf_s(Message, 256, L"RpcServerUseProtseqEp failed with code %i.\n", status);
			ServerWriteLogErrorTerminate(Message, status);
		}
	}

	// Registers the KMSServer interface.
	status = RpcServerRegisterIfEx
	(
		// Interface to register.
		KMSServer_v1_0_s_ifspec, 
		// Use the MIDL generated entry-point vector.
		NULL, 
		// Use the MIDL generated entry-point vector.
		NULL,
		// Interface Registration Flags
		RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH | RPC_IF_AUTOLISTEN, 
		// Maximum Calls
		RPC_C_LISTEN_MAX_CALLS_DEFAULT, 
		// No Security Callback Function
		NULL
	);
	
	if (status)
	{
		// Format Log Message
		WCHAR Message[256];
		swprintf_s(Message, 256, L"RpcServerRegisterIfEx failed with code %i.\n", status);
		ServerWriteLogErrorTerminate(Message, status);
	}

	ServerWriteLogInformation(L"\nKMS Server Emulator started successfully.\n");

	// Start to listen for remote procedure calls for all registered interfaces.
    // This call will not return until RpcMgmtStopServerListening is called or the program is exited.
	status = RpcServerListen
	(
		// Recommended minimum number of threads.
		1, 
		// Recommended maximum number of threads.
		RPC_C_LISTEN_MAX_CALLS_DEFAULT, 
		// Start listening now.
		0
	);

	if (status)
	{
		// Format Log Message
		WCHAR Message[256];
		swprintf_s(Message, 256, L"RpcServerListen failed with code %i.\n", status);
		ServerWriteLogErrorTerminate(Message, status);
	}
}

// Stop RPC Connection
void StopKMSServer()
{
	RpcMgmtStopServerListening(NULL);
    RpcServerUnregisterIf(NULL, NULL, FALSE);
}
#pragma endregion

#pragma region RPC Interface Functions
// RPC Function to Build and Send a KMS Server Response.
int ActivationResponse(handle_t IDL_handle, int requestSize, unsigned char *request, int *responseSize, unsigned char **response)
{
	// No Unreferenced Parameter Warnings
	UNREFERENCED_PARAMETER(IDL_handle);

	// Verify Request Size
	if (requestSize < 92)
	{
		return RPC_S_INVALID_ENDPOINT_FORMAT;
	}

	// KMS Protocol Version
	if (request[2] == 4 && request[0] == 0)
	{
		// Send Response to KMS Client
		*response = CreateResponseV4((REQUEST_V4 *)request, responseSize);

		// Log Sent Response
		ServerWriteLogInformation(L"Activation response (KMS V4.0) sent.\n");
		
		// Return to RPC Interface
		return RPC_S_OK;
	}
	else if (request[2] == 5 && request[0] == 0)
	{
		// Send Response to KMS Client
		*response = CreateResponseV5((REQUEST_V5 *)request, responseSize);

		// Log Sent Response
		ServerWriteLogInformation(L"Activation response (KMS V5.0) sent.\n");

		// Return to RPC Interface
		return RPC_S_OK;
	}
	else if (request[2] == 6 && request[0] == 0)
	{
		// Send Response to KMS Client
		*response = CreateResponseV6((REQUEST_V6 *)request, responseSize);

		// Log Sent Response
		ServerWriteLogInformation(L"Activation response (KMS V6.0) sent.\n");

		// Return to RPC Interface
		return RPC_S_OK;
	}
	else
	{
		// Unsupported Protocol
		return RPC_S_INVALID_VERS_OPTION;
	}
}
#pragma endregion

#pragma region KMS Server Response Generation Functions
// Create Base KMS Server Response Object and handle KMS PID and HWID.
DWORD CreateResponseBase(REQUEST* const Request, PBYTE const Response)
{
	// Generate KMS PID or use Command Argument
	WCHAR kmsPIDInstance[PID_BUFFER_SIZE] = { 0 };

	// Try to Get Application Specific KMS PID and HWID if running as KMS Server Service
	if (ServerSettings.RunAsService)
	{
		GetKMSPID(kmsPIDInstance, Request);
	}

	// No Specific KMS PID or not running as KMS Server Service
	if (!regex_match(kmsPIDInstance, wregex(L"^([0-9]{5})-([0-9]{5})-([0-9]{3})-([0-9]{6})-([0-9]{2})-([0-9]{4,5})-([0-9]{4}).([0-9]{4})-([0-9]{7})$")))
	{
		if (ServerSettings.GenerateRandomKMSPID)
		{
			// Build Random KMS PID
			CreateKMSPID(kmsPIDInstance, Request);

			// Format Log Message
			WCHAR Message[256];
			swprintf_s(Message, 256, L"\nKMS PID Generated: %s \n", kmsPIDInstance);
			ServerWriteLogInformation(Message);
		}
		else
		{
			// Use Global KMS PID from Settings
			StringCchCopyW(kmsPIDInstance, PID_BUFFER_SIZE, ServerSettings.KMSPID);
		}
	}

	// Get KMS PID Length
	DWORD kmsPIDLen = (DWORD)((wcslen(kmsPIDInstance) + 1) * sizeof(WCHAR));

	// Current pointer
	PBYTE current = Response;

	// Set KMS Protocol Minor Version & Major Version
	*(PDWORD)current = *(PDWORD)Request;
	current += sizeof(DWORD);

	// Set KMS PID Length
	*(PDWORD)current = kmsPIDLen;
	current += sizeof(DWORD);

	// Copy KMS PID
	memcpy(current, kmsPIDInstance, kmsPIDLen);
	current += kmsPIDLen;

	// Copy Client Machine ID
	memcpy(current, &Request->ClientMachineId, sizeof(GUID));
	current += sizeof(GUID);

	// Copy KMS Client Request Timestamp
	memcpy(current, &Request->RequestTime, sizeof(FILETIME));
	current += sizeof(FILETIME);

	// Set KMS Client Count Parameter
	*(PDWORD)current = ServerSettings.CurrentClientCount;
	current += sizeof(DWORD);

	// Set KMS Activation Interval Parameter
	*(PDWORD)current = ServerSettings.VLActivationInterval;
	current += sizeof(DWORD);

	// Set KMS Renewal Interval Parameter
	*(PDWORD)current = ServerSettings.VLRenewalInterval;
	current += sizeof(DWORD);

	// Return ResponseBase Size
	return (DWORD)(current - Response);
}

// Create Hashed KMS Server Response Data for KMS Protocol Version 4.
PBYTE CreateResponseV4(REQUEST_V4* const Request, int* const responseSize)
{
	// Allocate KMS Server Response Buffer
	BYTE buffer[MAX_RESPONSE_SIZE] = {0};

	// Create KMS Server Response Base
	int size = CreateResponseBase(&Request->RequestBase, buffer);

	// Create Hash
	GetHash(size, buffer, buffer + size);

	// Create Proper Response with Hash
	*responseSize = size + 16;
	PBYTE response = (PBYTE)midl_user_allocate(*responseSize);
	memcpy(response, buffer, *responseSize);

	// Return Response
	return response;
}

// Create Encrypted KMS Server Response Data for KMS Protocol Version 5.
PBYTE CreateResponseV5(REQUEST_V5* const Request, int* const responseSize)
{
	// Allocate Response Buffer
	BYTE buffer[MAX_RESPONSE_SIZE] = {0};

	// Current pointer
	PBYTE current = buffer;

	// Set KMS Protocol Minor Version & Major Version
	*(PDWORD)current = *(PDWORD)Request;
	current += sizeof(DWORD);
	
	// Store Response Salt pointer
	PBYTE ResponseSalt = current;

	// Copy Response Salt
	memcpy(current, Request->Salt, 16);
	current += 16;

	// AES-128 Decrypt
	DWORD DecryptSize = sizeof(Request->Salt) + sizeof(Request->RequestBase) + sizeof(Request->Pad);
	AESDecryptMessage(Request->Salt, Request->Salt, &DecryptSize);

	// Store Encrypt start pointer
	PBYTE EncryptStart = current;

	// Create Response Base Object
	current += CreateResponseBase(&Request->RequestBase, current);

	// Random Salt
	BYTE RandomSalt[16];

	// Seed Random Number Generator
	srand(GetTickCount());

	// Generate a Random Salt Key
	for(int i = 0; i < 16; i++)
	{
		RandomSalt[i] = rand() % 256;
		current[i] = Request->Salt[i] ^ ResponseSalt[i] ^ RandomSalt[i];
	}
	current += 16;

	// Create Hash
	GetHashSHA256(16, RandomSalt, current);
	current += 32;

	// Encrypted and Unencrypted size (KMS Protocol Major Version (2) + KMS Protocol Minor Version (2) + Salt (16))
	DWORD UnencryptedSize = 20;
    DWORD EncryptedSize = (DWORD)(current - EncryptStart);
	
	// AES-128 Encrypt
	AESEncryptMessage(ResponseSalt, EncryptStart, &EncryptedSize, MAX_RESPONSE_SIZE - UnencryptedSize);

	// Make proper response with correct size 
	*responseSize = EncryptedSize + UnencryptedSize;
	PBYTE response = (PBYTE)midl_user_allocate(*responseSize);
	memcpy(response, buffer, *responseSize);

	// Return Response
	return response;
}

// Create Encrypted KMS Server Response Data for KMS Protocol Version 6.
PBYTE CreateResponseV6(REQUEST_V6* const Request, int* const responseSize)
{
	// V6: AES key
	BYTE AES_V6_KEY[16] = {0xA9, 0x4A, 0x41, 0x95, 0xE2, 0x01, 0x43, 0x2D, 0x9B, 0xCB, 0x46, 0x04, 0x05, 0xD8, 0x4A, 0x21};

	// Allocate Response Buffer
	BYTE buffer[MAX_RESPONSE_SIZE] = {0};

	// Current pointer
	PBYTE current = buffer;

	// Set KMS Protocol Minor Version & Major Version
	*(PDWORD)current = *(PDWORD)Request;
	current += sizeof(DWORD);
	
	// Store Response Salt pointer
	PBYTE ResponseSalt = current;

	// Copy Response Salt
	memcpy(current, Request->Salt, 16);
	current += 16;

	// AES-128 Decrypt
	DWORD DecryptSize = sizeof(Request->Salt) + sizeof(Request->RequestBase) + sizeof(Request->Pad);

	// Modded AES-CBC Decrypt
	AesInit(AES_TYPE_128, AES_MODE_CBC, 0x04, AES_V6_KEY, Request->Salt);
	DecryptMessage(DecryptSize, Request->Salt);
	AesClear();

	// Store Encrypt start pointer
	PBYTE EncryptStart = current;

	// Create Response Base Object
	current += CreateResponseBase(&Request->RequestBase, current);

	// Random Salt
	BYTE RandomSalt[16];

	// Seed Random Number Generator
	srand(GetTickCount());

	// Generate a Random Salt Key
	for(int i = 0; i < 16; i++)
	{
		RandomSalt[i] = rand() % 256;
		current[i] = Request->Salt[i] ^ ResponseSalt[i] ^ RandomSalt[i];
	}
	current += 16;

	// Create Hash
	GetHashSHA256(16, RandomSalt, current);
	current += 32;

	#pragma region KMS HWID
	// Try to Get Application Specific KMS HWID if running as KMS Server Service
	QWORD kmsHWIDInstance = 0x0;
	if (ServerSettings.RunAsService)
	{
		GetKMSHWID(&kmsHWIDInstance, &Request->RequestBase);
	}

	// No Specific KMS HWID or not running as KMS Server Service
	if (kmsHWIDInstance == 0x0)
	{
		// Use Global KMS PID from Settings
		kmsHWIDInstance = ServerSettings.KMSHWID;
	}

	// Machine Hardware Hash
	*(PQWORD) current = kmsHWIDInstance;
	current += 8;
	#pragma endregion
	
	//  HMAC message buffer
	BYTE Hmac_msg[256];

	// Xor2 and Hmac_msg
	for(int i = 0; i < 16; i++)
	{
		Hmac_msg[i] = current[i] = Request->Salt[i] ^ ResponseSalt[i];
	}
	current += 16;

	//  HMAC size
	DWORD Hmac_size = current - EncryptStart;
	memcpy(Hmac_msg + 16, EncryptStart, Hmac_size);
	Hmac_size += 16;

	// HMAC-SHA256
	BYTE Hmac_hash[32];
	GetHmacKey(&Request->RequestBase.RequestTime, Hmac_keyblob.rgbKeyData);
	GetHmacSHA256(Hmac_size, Hmac_msg, Hmac_hash);
	memcpy(current, Hmac_hash + 16, 16);
	current += 16;

	// Encrypted and Unencrypted size (KMS Protocol Major Version (2) + KMS Protocol Minor Version (2) + Salt (16))
    DWORD EncryptSize = (DWORD)(current - EncryptStart);
	
	// PKCS5 Padding
	BYTE bPadding =(~EncryptSize + 1) & 0x0f;
	if(bPadding == 0){
		bPadding = 16;
	}

	memset(current, bPadding, bPadding);
	EncryptSize += bPadding;

	// Modded AES-CBC Encrypt
	AesInit(AES_TYPE_128, AES_MODE_CBC, bPadding, AES_V6_KEY, ResponseSalt);
	EncryptMessage(EncryptSize, EncryptStart);
	AesClear();

	// Make proper response with correct size 
	*responseSize = EncryptSize + 20;
	PBYTE response = (PBYTE)midl_user_allocate(*responseSize);
	memcpy(response, buffer, *responseSize);

	// Return Response
	return response;
}
#pragma endregion

#pragma region Parameter Validation Functions
// Validate KMS Port Parameter
void ServerValidateKMSPort(WCHAR* KMSPort)
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
				ServerWriteLogErrorTerminate(Message, -1);
			}
			else
			{
				// Apply Setting
				StringCchCopyW(ServerSettings.KMSPort, PORT_BUFFER_SIZE, KMSPort);

				// Format Log Message
				WCHAR Message[256];
				swprintf_s(Message, 256, L"KMS Port: %s \n", KMSPort);
				ServerWriteLogInformation(Message);
			}
		}
		else			
		{
			// Format Log Message
			WCHAR Message[256];
			swprintf_s(Message, 256, L"Invalid KMS Port! %s is not a valid argument.\n", KMSPort);
			ServerWriteLogErrorTerminate(Message, -1);
		}
	}
}

// Validate KMS PID Parameter
void ServerValidateKMSPID(WCHAR* KMSPID)
{
	// Check if KMS PID should be Random
	if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, KMSPID, -1, L"RandomKMSPID", -1) == CSTR_EQUAL)
	{
		ServerSettings.GenerateRandomKMSPID = true;
	}
	// Check if KMS PID is Valid
	else if (regex_match(KMSPID, wregex(L"^([0-9]{5})-([0-9]{5})-([0-9]{3})-([0-9]{6})-([0-9]{2})-([0-9]{4,5})-([0-9]{4}).([0-9]{4})-([0-9]{7})$")))
	{
		// Apply Setting
		StringCchCopyW(ServerSettings.KMSPID, PID_BUFFER_SIZE, KMSPID);

		// Disable Random KMSPID Generation
		ServerSettings.GenerateRandomKMSPID = false;

		// Format Log Message
		WCHAR Message[256];
		swprintf_s(Message, 256, L"KMS PID: %s \n", KMSPID);
		ServerWriteLogInformation(Message);
	}
	else
	{
		// Format Log Message
		WCHAR Message[256];
		swprintf_s(Message, 256, L"Invalid KMS PID! %s is not a valid argument.\n", KMSPID);
		ServerWriteLogErrorTerminate(Message, -1);
	}
}

// Validate KMS HWID Parameter
void ServerValidateKMSHWID(WCHAR* KMSHWID)
{
	// Check if the KMS Port is not the Default
	if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, KMSHWID, -1, L"DefaultKMSHWID", -1) != CSTR_EQUAL)
	{
		// Check if KMS HWID is Valid Hex String
		if (regex_match(KMSHWID, wregex(L"^[a-fA-F0-9]{16}$")))
		{
			// Apply Setting
			ServerSettings.KMSHWID = wcstoull(KMSHWID, NULL, 16);

			// Format Log Message
			WCHAR Message[256];
			swprintf_s(Message, 256, L"KMS HWID: %s \n", KMSHWID);
			ServerWriteLogInformation(Message);
		}
		else
		{
			// Format Log Message
			WCHAR Message[256];
			swprintf_s(Message, 256, L"Invalid KMS Hardware ID! %s is not a valid argument.\n", KMSHWID);
			ServerWriteLogErrorTerminate(Message, -1);
		}
	}
}

// Validate KMS Activation Interval Parameter
void ServerValidateVLActivationInterval(int VLActivationInterval)
{
	// Check if KMS Activation Interval is Valid Range
	if (VLActivationInterval < 15 || VLActivationInterval > 43200)
	{
		// Format Log Message
		WCHAR Message[256];
		swprintf_s(Message, 256, L"Invalid KMS Activation Interval Range! %i is not a valid argument.\n", VLActivationInterval);
		ServerWriteLogErrorTerminate(Message, -1);
	}
	else
	{
		// Apply Setting
		ServerSettings.VLActivationInterval = VLActivationInterval;

		// Format Log Message
		WCHAR Message[256];
		swprintf_s(Message, 256, L"KMS Activation Interval: %i minutes \n", VLActivationInterval);
		ServerWriteLogInformation(Message);
    }
}

// Validate KMS Activation Interval Parameter
void ServerValidateVLRenewalInterval(int VLRenewalInterval)
{
	// Check if KMS Renewal Interval is Valid Range
	if (VLRenewalInterval < 15 || VLRenewalInterval > 43200)
	{
		// Format Log Message
		WCHAR Message[256];
		swprintf_s(Message, 256, L"Invalid KMS Renewal Interval Range! %i is not a valid argument.\n", VLRenewalInterval);
		ServerWriteLogErrorTerminate(Message, -1);
	}
	else
	{
		// Apply Setting
		ServerSettings.VLRenewalInterval = VLRenewalInterval;

		// Format Log Message
		WCHAR Message[256];
		swprintf_s(Message, 256, L"KMS Renewal Interval: %i minutes \n", VLRenewalInterval);
		ServerWriteLogInformation(Message);
    }
}
#pragma endregion

#pragma region Logging Functions
// Log an informational message to the Console or Windows Application Event Log.
void ServerWriteLogInformation(WCHAR* const Message)
{
	// Log Message Buffer
	WCHAR logMessage[256];

	// Write Log Message to Buffer
	StringCbPrintfW(logMessage, 256, Message);

	// Choose Log Source
	if (ServerSettings.RunAsService)
	{
		// Output to Windows Event Log: Qualifiers: 16384, EventId: 12290
		ServerWriteEventLogEntry(0x40003002, logMessage, EVENTLOG_INFORMATION_TYPE);
	}
	else
	{
		// Output to Console
		wprintf(L"%s", logMessage);
	}
}

// Log an error message to the Console or Windows Application Event Log.
void ServerWriteLogError(WCHAR* const Message)
{
	// Log Message Buffer
	WCHAR logMessage[256];

	// Write Log Message to Buffer
	StringCbPrintfW(logMessage, 256, Message);

	// Choose Log Source
	if (ServerSettings.RunAsService)
	{
		// Output to Windows Event Log: Qualifiers: 16384, EventId: 902
		ServerWriteEventLogEntry(0x40000386, logMessage, EVENTLOG_ERROR_TYPE);
	}
	else
	{
		// Output to Console
		wprintf(L"%s", logMessage);
	}
}

// Log an error message to the Console or Windows Application Event Log and terminate program.
void ServerWriteLogErrorTerminate(WCHAR* const Message, int ExitCode)
{
	// Call ServerWriteLogError
	ServerWriteLogError(Message);

	if (!ServerSettings.RunAsService)
	{
		// Exit Program
		exit(ExitCode);
	}
	else
	{
		// Exit Service
		ServerServiceStatus.dwCurrentState       = SERVICE_STOPPED; 
		ServerServiceStatus.dwWin32ExitCode      = ExitCode; 
		SetServiceStatus(ServerServiceHandle, &ServerServiceStatus); 
	}
}

// Log a message to the Windows Application Event Log.
void ServerWriteEventLogEntry(DWORD dwIdentifier, WCHAR* const lpszMessage, WORD wType)
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