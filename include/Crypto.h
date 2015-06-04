//---------------------------------------------------------------------------
// Header Guard
#pragma once

// Includes and Namespaces
#include <windows.h>

// Constants
#define AES_TYPE_128 0
#define AES_TYPE_192 1
#define AES_TYPE_256 2

#define AES_MODE_ECB 0
#define AES_MODE_CBC 1
#define AES_MODE_CFB 2
#define AES_MODE_OFB 3
#define AES_MODE_CTR 4

//---------------------------------------------------------------------------
// Function Prototypes
void AESDecryptMessage(PBYTE const IV, PBYTE const Message, PDWORD const MessageSize);
void AESEncryptMessage(PBYTE const IV, PBYTE const Message, PDWORD const MessageSize, DWORD BufferLen);

BYTE MULx2(BYTE bIn);
BYTE MULx3(BYTE bIn);
DWORD AesInit(DWORD dwType, DWORD dwMode, BYTE bPadding, PBYTE pbKey, PBYTE pbIV);
DWORD AesClear(void);
void DecryptMessage(int MessageSize, PBYTE Message);
void EncryptMessage(int MessageSize, PBYTE Message);
//---------------------------------------------------------------------------