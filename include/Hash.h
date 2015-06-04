//---------------------------------------------------------------------------
// Header Guard
#pragma once

// Includes and Namespaces
#include <windows.h>
//---------------------------------------------------------------------------

// HMAC-SHA256 key blob structure
struct HMAC_KEYBLOB {
    BLOBHEADER hdr;
    DWORD dwKeySize;
    BYTE rgbKeyData[16];
};

// Function Prototypes
void GetHash(DWORD MessageSize, PBYTE const Message, PBYTE const hash);
void GetHashSHA256(DWORD dataSize, PBYTE const data, PBYTE const Hash);
void GetHmacKey(FILETIME* timestamp, PBYTE hmackey);
void GetHmacSHA256(DWORD dwDataLen, PBYTE const pbData, PBYTE const pbHash);
//--------------------------------------------------------------------------