// Includes and Namespaces
#include "KMSServerLib.h"

// KMS Server Console Main EntryPoint
int wmain(int argc, wchar_t* argv[]) 
{
	// Get Application Parameters
	LoadServerParameters(argc, argv, false);

	// Start KMS Server
	StartKMSServer();

	// Progrem Stopped
	return 0;
}