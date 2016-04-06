//---------------------------------------------------------------------------
// Header Guard
#pragma once

// Includes and Namespaces
#include <windows.h>
#include <Strsafe.h>
#include "CoreKMS.h"
//---------------------------------------------------------------------------
// Function Prototypes
void LoadClientParameters(int argc, wchar_t *argv[], bool RunAsService);
void StartKMSClient();
PBYTE CreateRequest();
void CreateRequestBase(REQUEST* const Request);
PBYTE CreateRequestV4();
PBYTE CreateRequestV5();
PBYTE CreateRequestV6();
void ReadResponseV4(RESPONSE_V4& Response_v4, int responseSize, PBYTE response);
void ReadResponseV5(RESPONSE_V5& Response_v5, int responseSize, PBYTE response);
void ReadResponseV6(RESPONSE_V6& Response_v5, int responseSize, PBYTE response);
int SendRequest(PBYTE request, const int requestsSent,  int* const requestsNeeded);
void ClientValidateKMSPort(WCHAR* KMSPort);
void ClientValidateKMSHost(WCHAR* KMSHost);
void ClientValidateKMSClientMode(WCHAR* KMSClientMode);
void ClientWriteLogInformation(WCHAR* const Message);
void ClientWriteLogError(WCHAR* const Message);
void ClientWriteLogErrorTerminate(WCHAR* const Message, int ExitCode);
void ClientWriteEventLogEntry(DWORD dwIdentifier, WCHAR* const lpszMessage, WORD wType);
//---------------------------------------------------------------------------