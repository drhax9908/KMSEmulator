//---------------------------------------------------------------------------
// Header Guard
#pragma once

// Includes and Namespaces
#include <windows.h>
#include <regex>
#include <Strsafe.h>
#include <string>
#include "CoreKMS.h"

// Function Prototypes
void CreateKMSPID(WCHAR* const KMSPID, REQUEST* const Request);
void GetKMSPID(WCHAR* const KMSPID, REQUEST* const Request);
//---------------------------------------------------------------------------