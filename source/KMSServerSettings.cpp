// Includes and Namespaces
#include "KMSServerSettings.h"

// KMS Server Parameters
WCHAR KMSServerSettings::KMSPID[PID_BUFFER_SIZE];
QWORD KMSServerSettings::KMSHWID;
WCHAR KMSServerSettings::KMSPort[PORT_BUFFER_SIZE];
DWORD KMSServerSettings::CurrentClientCount;
DWORD KMSServerSettings::VLActivationInterval;
DWORD KMSServerSettings::VLRenewalInterval;

// KMS Server Program Control
bool KMSServerSettings::GenerateRandomKMSPID;
bool KMSServerSettings::RunAsService;

// Process Termination Control Variables
bool KMSServerSettings:: KillProcesses;

// Set Default Settings
void KMSServerSettings::Initialize() 
{
	StringCchCopyW(KMSPID, PID_BUFFER_SIZE, L"55041-00168-305-246209-03-1033-7600.0000-0522010");
	KMSHWID = 0x364F463A8863D35F;
	StringCchCopyW(KMSPort, PORT_BUFFER_SIZE, L"1688");
	CurrentClientCount = 26;
	VLActivationInterval = 120;
	VLRenewalInterval = 10080;
	GenerateRandomKMSPID = true;
};
