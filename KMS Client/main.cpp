// Includes and Namespaces
#include "KMSClientLib.h"

// KMS Client Console Main EntryPoint
int wmain(int argc, wchar_t* argv[]) 
{
	// Get Application Parameters
	LoadClientParameters(argc, argv, false);

	// Start KMS Client
	StartKMSClient();

	// Progrem Stopped
	return 0;
}