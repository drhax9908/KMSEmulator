//---------------------------------------------------------------------------
// Header Guard
#pragma once

// Includes and Namespaces
#include <windows.h>
#include <Strsafe.h>
#include "CoreKMS.h"
//---------------------------------------------------------------------------
// Class Prototypes

// Contains all KMS Server Parameters and Settings.
class KMSServerSettings
{
public:
	// KMS Server Parameters
	static WCHAR KMSPID[PID_BUFFER_SIZE];
	static QWORD KMSHWID;
	static WCHAR KMSPort[PORT_BUFFER_SIZE];
	static DWORD CurrentClientCount;
	static DWORD VLActivationInterval;
	static DWORD VLRenewalInterval;

	// KMS Server Program Control
	static bool GenerateRandomKMSPID;
	static bool RunAsService;

	// Process Termination Control Variables
	static bool KillProcesses;

	// Set Default Settings
	static void Initialize();
};
//---------------------------------------------------------------------------