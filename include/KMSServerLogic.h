//---------------------------------------------------------------------------
// Header Guard
#pragma once

// Includes and Namespaces
#include <windows.h>
#include <Strsafe.h>
#include "CoreKMS.h"
//---------------------------------------------------------------------------
// Function Prototypes
void LoadServerParameters(int argc, wchar_t* argv[], bool RunAsService);
void StartKMSServer();
void StopKMSServer();
DWORD CreateResponseBase(REQUEST* const Request, PBYTE const Response);
PBYTE CreateResponseV4(REQUEST_V4* const Request, int* const responseSize);
PBYTE CreateResponseV5(REQUEST_V5* const Request, int* const responseSize);
PBYTE CreateResponseV6(REQUEST_V6* const Request, int* const responseSize);
void ServerValidateKMSPort(WCHAR* KMSPort);
void ServerValidateKMSPID(WCHAR* KMSPID);
void ServerValidateKMSHWID(WCHAR* KMSHWID);
void ServerValidateVLActivationInterval(int VLActivationInterval);
void ServerValidateVLRenewalInterval(int VLRenewalInterval);
void ServerWriteLogInformation(WCHAR* const Message);
void ServerWriteLogError(WCHAR* const Message);
void ServerWriteLogErrorTerminate(WCHAR* const Message, int ExitCode);
void ServerWriteEventLogEntry(DWORD dwIdentifier, WCHAR* const lpszMessage, WORD wType);
void GetHmacKey(FILETIME* timestamp, PBYTE hmackey);
void GetHmacSHA256(DWORD dwDataLen, PBYTE const pbData, PBYTE const pbHash);
//---------------------------------------------------------------------------