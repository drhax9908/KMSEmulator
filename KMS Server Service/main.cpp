// Includes and Namespaces
#include "KMSServerLib.h"

// Function Prototypes
void ServiceMain(int argc, char** argv); 
void ControlHandler(DWORD code); 

// Windows Service Parameters
extern SERVICE_STATUS ServerServiceStatus; 
extern SERVICE_STATUS_HANDLE ServerServiceHandle;
WCHAR ServiceName[] = L"KMSServerService";
 
// KMS Server Service Main EntryPoint
int wmain(int argc, wchar_t* argv[]) 
{ 
	// Get Application Parameters
	LoadServerParameters(argc, argv, true);

	// Windows Service Parameters
	SERVICE_TABLE_ENTRY ServiceTable[2] = {0};
	ServiceTable[0].lpServiceName = ServiceName;
	ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

	// Start Service Control Dispatcher Thread for our Service
	StartServiceCtrlDispatcher(ServiceTable);

	// Service Stopped
	return 0;
}

// KMS Server Service EntryPoint
void ServiceMain(int argc, char* argv[]) 
{ 
	// No Unreferenced Parameter Warnings
	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	// Register Control Handler
	ServerServiceHandle = RegisterServiceCtrlHandlerW(ServiceName, (LPHANDLER_FUNCTION)ControlHandler);

	// RegisterServiceCtrlHandlerW returned NULL PTR
	if (ServerServiceHandle == NULL)
     { 
        // Registering Control Handler failed
        return; 
    }  

    ServerServiceStatus.dwServiceType        = SERVICE_WIN32; 
    ServerServiceStatus.dwCurrentState       = SERVICE_RUNNING; 
	ServerServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_STOP;
	ServerServiceStatus.dwWin32ExitCode = ERROR_SUCCESS;
    ServerServiceStatus.dwServiceSpecificExitCode = NULL;
	ServerServiceStatus.dwCheckPoint = NULL;
	ServerServiceStatus.dwWaitHint = NULL;

	// Report Service Status to SCM.
	SetServiceStatus(ServerServiceHandle, &ServerServiceStatus);
 	
	// Start KMS Server
	StartKMSServer();
}

// Control Handler
void ControlHandler(DWORD code) 
{ 
    switch(code)
	{
		case SERVICE_CONTROL_SHUTDOWN:
		case SERVICE_CONTROL_STOP:
			ServerServiceStatus.dwWin32ExitCode = ERROR_SUCCESS;
			ServerServiceStatus.dwCurrentState = SERVICE_STOPPED;
			break;
		case SERVICE_USER_DEFINED_CONTROL:
			ServerServiceStatus.dwWin32ExitCode = ERROR_BAD_CONFIGURATION;
			ServerServiceStatus.dwCurrentState = SERVICE_STOPPED;
			break;
	}
 
    // Report Service Status
	SetServiceStatus(ServerServiceHandle, &ServerServiceStatus);
} 