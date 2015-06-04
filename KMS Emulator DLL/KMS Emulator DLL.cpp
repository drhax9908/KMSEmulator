// KMS Emulator DLL.cpp : Defines the exported functions for the DLL application.
//

// Includes and Namespaces
#include "stdafx.h"

// DLL Export Function Prototypes
extern "C" __declspec(dllexport) void RunKMSClient(int argc, wchar_t *argv[], bool RunAsService);
extern "C" __declspec(dllexport) void RunKMSServer(int argc, wchar_t *argv[], bool RunAsService);
extern "C" __declspec(dllexport) void KillKMSServer();

// Load KMS Client Options and Start KMS Client
extern "C" __declspec(dllexport) void RunKMSClient(int argc, wchar_t *argv[], bool RunAsService)
{
	LoadClientParameters(argc, argv, RunAsService);
	StartKMSClient();
}

// Load KMS Server Options and Start KMS Server
extern "C" __declspec(dllexport) void RunKMSServer(int argc, wchar_t *argv[], bool RunAsService)
{
	LoadServerParameters(argc, argv, RunAsService);
	StartKMSServer();
}

// Stop KMS Server
extern "C" __declspec(dllexport) void KillKMSServer()
{
	StopKMSServer();
}