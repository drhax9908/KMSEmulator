// Includes and Namespaces
#include "Crypto.h"

// AES 128-bit key blob structure
struct AES_128_KEYBLOB 
{
    BLOBHEADER hdr;
    DWORD dwKeySize;
    BYTE rgbKeyData[16];
};

// Static AES Session Key
static const AES_128_KEYBLOB keyBlob = 
{
	// Type, Version, Algorithm
    {PLAINTEXTKEYBLOB, CUR_BLOB_VERSION, NULL, CALG_AES_128},
	// Blocklength
    16,
	// Key
    {0xCD, 0x7E, 0x79, 0x6F, 0x2A, 0xB2, 0x5D, 0xCB, 0x55, 0xFF, 0xC8, 0xEF, 0x83, 0x64, 0xC4, 0x70}
};

// Default Type
static DWORD Type=AES_TYPE_128;

// Default Mode
static DWORD Mode=AES_MODE_ECB;

// Default Padding
static BYTE Padding=0x00;

// Static Key Pointer
static PBYTE pKey=NULL;

// Static IV Pointer
static PBYTE pIV=NULL;

// Init
static bool IsInit=false;

// Nb: Number of blocks, Nr: Number of rounds, Nk: Number of keys
static DWORD Nb,Nr,Nk;

// Static SubKeys Pointer
static PDWORD pSubKeys=NULL;

// RCon
static BYTE Rcon[11]= {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

#pragma region Tables

// Substitution Table
static BYTE SubTable[256]=
{
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// Inverse Substitution Table
static BYTE InvSubTable[256]=
{
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

#pragma endregion

// WinApi: AES-128 CBC PKCS5-Padding Encryption
void AESEncryptMessage(PBYTE const IV, PBYTE const Message, PDWORD const MessageSize, DWORD BufferLen)
{
    HCRYPTPROV hProv = NULL;
    HCRYPTKEY hKey = NULL;

	if(!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	   return;

    CryptImportKey(hProv, (PBYTE)&keyBlob, sizeof(keyBlob), NULL, NULL, &hKey);
    CryptSetKeyParam(hKey, KP_IV, IV, NULL);
    CryptEncrypt(hKey, NULL, true, NULL, Message, MessageSize, BufferLen);

	if(hKey)
		CryptDestroyKey(hKey);

	if(hProv)
		CryptReleaseContext(hProv, NULL);
}

// WinApi: AES-128 CBC PKCS5-Padding Decryption
void AESDecryptMessage(PBYTE const IV, PBYTE const Message, PDWORD const MessageSize)
{
    HCRYPTPROV hProv = NULL;
    HCRYPTKEY hKey = NULL;

    if(!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		return;

    CryptImportKey(hProv, (PBYTE)&keyBlob, sizeof(keyBlob), NULL, NULL, &hKey);
    CryptSetKeyParam(hKey, KP_IV, IV, NULL);
    CryptDecrypt(hKey, NULL, true, NULL, Message, MessageSize);

    if(hKey)
		CryptDestroyKey(hKey);

	if(hProv)
		CryptReleaseContext(hProv, NULL);
}

#pragma region Math

// MUL x 2
BYTE MULx2(BYTE bIn)
{
    BYTE bOut;
    bOut=(bIn<<1);

    if ((bIn & 0x80) != 0x00)
        bOut^=0x1B;

    return bOut;
};

// MUL x 3
BYTE MULx3(BYTE bIn)
{
    BYTE bOut;
    bOut=MULx2(bIn)^bIn;

    return bOut;
};

// MUL x 4
BYTE MULx4(BYTE bIn)
{
    BYTE bOut;
    bOut=MULx2(bIn);
    bOut=MULx2(bOut);

    return bOut;
};

// MUL x 8
BYTE MULx8(BYTE bIn)
{
    BYTE bOut;
    bOut=MULx2(bIn);
    bOut=MULx2(bOut);
    bOut=MULx2(bOut);

    return bOut;
};

// MUL x 9
BYTE MULx9(BYTE bIn)
{
    BYTE bOut;
    bOut=MULx8(bIn)^bIn;

    return bOut;
};

// MUL x B
BYTE MULxB(BYTE bIn)
{
    BYTE bOut;
    bOut=MULx8(bIn)^MULx2(bIn)^bIn;

    return bOut;
};

// MUL x D
BYTE MULxD(BYTE bIn)
{
    BYTE bOut;
    bOut=MULx8(bIn)^MULx4(bIn)^bIn;

    return bOut;
};

// MUL x E
BYTE MULxE(BYTE bIn)
{
    BYTE bOut;
    bOut=MULx8(bIn)^MULx4(bIn)^MULx2(bIn);
    return bOut;
};

// SBOX
BYTE SBox(BYTE bIn)
{
    return SubTable[bIn];
};

// Inverse SBOX
BYTE InvSBox(BYTE bIn)
{
    return InvSubTable[bIn];
};

// Substitute Word
DWORD SubWord(DWORD dwIn)
{
    DWORD dwOut;

    (*((PBYTE)(&dwOut)))=SBox(*((PBYTE)(&dwIn)));
    (*(((PBYTE)(&dwOut))+1))=SBox(*(((PBYTE)(&dwIn))+1));
    (*(((PBYTE)(&dwOut))+2))=SBox(*(((PBYTE)(&dwIn))+2));
    (*(((PBYTE)(&dwOut))+3))=SBox(*(((PBYTE)(&dwIn))+3));

    return dwOut;
};

// Rotate Word
DWORD RotWord(DWORD dwIn)
{
    DWORD dwOut;

    (*((PBYTE)(&dwOut)))=(*(((PBYTE)(&dwIn))+1));
    (*(((PBYTE)(&dwOut))+1))=(*(((PBYTE)(&dwIn))+2));
    (*(((PBYTE)(&dwOut))+2))=(*(((PBYTE)(&dwIn))+3));
    (*(((PBYTE)(&dwOut))+3))=(*((PBYTE)(&dwIn)));

    return dwOut;
};

// Substitute Bytes
void SubBytes(PBYTE pBytes)
{
    DWORD i;
    BYTE bIn[16];

    for(i=0 ; i<16 ; i++)
        bIn[i]=pBytes[i];

    for(i=0 ; i<16 ; i++)
        pBytes[i]=SBox(bIn[i]);
};

// Shift Rows
void ShiftRows(PBYTE pBytes)
{
    DWORD i;
    BYTE bIn[16];

    for(i=0 ; i<16 ; i++)
        bIn[i]=pBytes[i];

    pBytes[0]=bIn[0];
    pBytes[1]=bIn[5];
    pBytes[2]=bIn[10];
    pBytes[3]=bIn[15];
    pBytes[4]=bIn[4];
    pBytes[5]=bIn[9];
    pBytes[6]=bIn[14];
    pBytes[7]=bIn[3];
    pBytes[8]=bIn[8];
    pBytes[9]=bIn[13];
    pBytes[10]=bIn[2];
    pBytes[11]=bIn[7];
    pBytes[12]=bIn[12];
    pBytes[13]=bIn[1];
    pBytes[14]=bIn[6];
    pBytes[15]=bIn[11];
};

// Mix Columns
void MixColumns(PBYTE pBytes)
{
    DWORD i;
    BYTE bIn[16];

    for(i=0 ; i<16 ; i++)
        bIn[i]=pBytes[i];

    pBytes[0] = MULx2(bIn[0]) ^ MULx3(bIn[1]) ^ bIn[2] ^ bIn[3];
    pBytes[1] = bIn[0] ^ MULx2(bIn[1]) ^ MULx3(bIn[2]) ^ bIn[3];
    pBytes[2] = bIn[0] ^ bIn[1] ^ MULx2(bIn[2]) ^ MULx3(bIn[3]);
    pBytes[3] = MULx3(bIn[0]) ^ bIn[1] ^ bIn[2] ^ MULx2(bIn[3]);
    pBytes[4] = MULx2(bIn[4]) ^ MULx3(bIn[5]) ^ bIn[6] ^ bIn[7];
    pBytes[5] = bIn[4] ^ MULx2(bIn[5]) ^ MULx3(bIn[6]) ^ bIn[7];
    pBytes[6] = bIn[4] ^ bIn[5] ^ MULx2(bIn[6]) ^ MULx3(bIn[7]);
    pBytes[7] = MULx3(bIn[4]) ^ bIn[5] ^ bIn[6] ^ MULx2(bIn[7]);
    pBytes[8] = MULx2(bIn[8]) ^ MULx3(bIn[9]) ^ bIn[10] ^ bIn[11];
    pBytes[9] = bIn[8] ^ MULx2(bIn[9]) ^ MULx3(bIn[10]) ^ bIn[11];
    pBytes[10] = bIn[8] ^ bIn[9] ^ MULx2(bIn[10]) ^ MULx3(bIn[11]);
    pBytes[11] = MULx3(bIn[8]) ^ bIn[9] ^ bIn[10] ^ MULx2(bIn[11]);
    pBytes[12] = MULx2(bIn[12]) ^ MULx3(bIn[13]) ^ bIn[14] ^ bIn[15];
    pBytes[13] = bIn[12] ^ MULx2(bIn[13]) ^ MULx3(bIn[14]) ^ bIn[15];
    pBytes[14] = bIn[12] ^ bIn[13] ^ MULx2(bIn[14]) ^ MULx3(bIn[15]);
    pBytes[15] = MULx3(bIn[12]) ^ bIn[13] ^ bIn[14] ^ MULx2(bIn[15]);
};

// Add Round Key
void AddRoundKey(PBYTE pState, DWORD Round)
{
    (*((PDWORD)pState)) ^= pSubKeys[4*Round];
    (*(((PDWORD)pState)+1)) ^= pSubKeys[4*Round+1];
    (*(((PDWORD)pState)+2)) ^= pSubKeys[4*Round+2];
    (*(((PDWORD)pState)+3)) ^= pSubKeys[4*Round+3];
};

// Inverse Substitute Bytes
void InvSubBytes(PBYTE pBytes)
{
    DWORD i;
    BYTE bIn[16];

    for(i=0 ; i<16 ; i++)
        bIn[i]=pBytes[i];

    for(i=0 ; i<16 ; i++)
        pBytes[i]=InvSBox(bIn[i]);
};

// Inverse Shift Rows
void InvShiftRows(PBYTE pBytes)
{
    DWORD i;
    BYTE bIn[16];

    for(i=0 ; i<16 ; i++)
        bIn[i]=pBytes[i];

    pBytes[0]=bIn[0];
    pBytes[1]=bIn[13];
    pBytes[2]=bIn[10];
    pBytes[3]=bIn[7];
    pBytes[4]=bIn[4];
    pBytes[5]=bIn[1];
    pBytes[6]=bIn[14];
    pBytes[7]=bIn[11];
    pBytes[8]=bIn[8];
    pBytes[9]=bIn[5];
    pBytes[10]=bIn[2];
    pBytes[11]=bIn[15];
    pBytes[12]=bIn[12];
    pBytes[13]=bIn[9];
    pBytes[14]=bIn[6];
    pBytes[15]=bIn[3];
};

// Inverse Mix Columns
void InvMixColumns(PBYTE pBytes)
{
    DWORD i;
    BYTE bIn[16];

    for(i=0 ; i<16 ; i++)
        bIn[i]=pBytes[i];

    pBytes[0] = MULxE(bIn[0]) ^ MULxB(bIn[1]) ^ MULxD(bIn[2]) ^ MULx9(bIn[3]);
    pBytes[1] = MULx9(bIn[0]) ^ MULxE(bIn[1]) ^ MULxB(bIn[2]) ^ MULxD(bIn[3]);
    pBytes[2] = MULxD(bIn[0]) ^ MULx9(bIn[1]) ^ MULxE(bIn[2]) ^ MULxB(bIn[3]);
    pBytes[3] = MULxB(bIn[0]) ^ MULxD(bIn[1]) ^ MULx9(bIn[2]) ^ MULxE(bIn[3]);
    pBytes[4] = MULxE(bIn[4]) ^ MULxB(bIn[5]) ^ MULxD(bIn[6]) ^ MULx9(bIn[7]);
    pBytes[5] = MULx9(bIn[4]) ^ MULxE(bIn[5]) ^ MULxB(bIn[6]) ^ MULxD(bIn[7]);
    pBytes[6] = MULxD(bIn[4]) ^ MULx9(bIn[5]) ^ MULxE(bIn[6]) ^ MULxB(bIn[7]);
    pBytes[7] = MULxB(bIn[4]) ^ MULxD(bIn[5]) ^ MULx9(bIn[6]) ^ MULxE(bIn[7]);
    pBytes[8] = MULxE(bIn[8]) ^ MULxB(bIn[9]) ^ MULxD(bIn[10]) ^ MULx9(bIn[11]);
    pBytes[9] = MULx9(bIn[8]) ^ MULxE(bIn[9]) ^ MULxB(bIn[10]) ^ MULxD(bIn[11]);
    pBytes[10] = MULxD(bIn[8]) ^ MULx9(bIn[9]) ^ MULxE(bIn[10]) ^ MULxB(bIn[11]);
    pBytes[11] = MULxB(bIn[8]) ^ MULxD(bIn[9]) ^ MULx9(bIn[10]) ^ MULxE(bIn[11]);
    pBytes[12] = MULxE(bIn[12]) ^ MULxB(bIn[13]) ^ MULxD(bIn[14]) ^ MULx9(bIn[15]);
    pBytes[13] = MULx9(bIn[12]) ^ MULxE(bIn[13]) ^ MULxB(bIn[14]) ^ MULxD(bIn[15]);
    pBytes[14] = MULxD(bIn[12]) ^ MULx9(bIn[13]) ^ MULxE(bIn[14]) ^ MULxB(bIn[15]);
    pBytes[15] = MULxB(bIn[12]) ^ MULxD(bIn[13]) ^ MULx9(bIn[14]) ^ MULxE(bIn[15]);
};

// Key Expansion
void KeyExpansion(void)
{
    DWORD i,Temp;

    for(i=0 ; i<Nk ; i++){
        (*(((PBYTE)pSubKeys)+4*i))=pKey[4*i];
        (*(((PBYTE)pSubKeys)+4*i+1))=pKey[4*i+1];
        (*(((PBYTE)pSubKeys)+4*i+2))=pKey[4*i+2];
        (*(((PBYTE)pSubKeys)+4*i+3))=pKey[4*i+3];
    };

    for(i=Nk ; i<(Nb*(Nr+1)) ; i++){
        Temp=pSubKeys[i-1];

        if (((i/Nk)*Nk) == i){
            Temp=((SubWord(RotWord(Temp)))^Rcon[i/Nk]);
        }else{
            if ((Nk>6)&&((i-Nk*(i/Nk)) == 4))
                Temp=SubWord(Temp);
        };

        pSubKeys[i]=((pSubKeys[i-Nk])^Temp);
    };
};

// Do Cipher
void DoCipher(PBYTE pIn, PBYTE pOut)
{
    BYTE State[16];
    DWORD Round;
    DWORD i;

    for(i=0 ; i<16 ; i++)
        State[i]=pIn[i];

    AddRoundKey(State,0);

    for(Round=1 ; Round<Nr ; Round++){
        SubBytes(State);
        ShiftRows(State);
        MixColumns(State);

		// KMS V6
		if(Round == 4){
			State[0] ^= 0x73;
		}else if(Round == 6){
			State[0] ^= 0x09;
		}else if(Round == 8){
			State[0] ^= 0xE4;
		}

        AddRoundKey(State,Round);
    };

    SubBytes(State);
    ShiftRows(State);
    AddRoundKey(State,Nr);

    for(i=0 ; i<16 ; i++)
        pOut[i]=State[i];
};

// Do Inverse Cipher
void DoInvCipher(PBYTE pIn, PBYTE pOut)
{
    BYTE State[16];
    DWORD Round;
    DWORD i;

    for(i=0 ; i<16 ; i++)
        State[i]=pIn[i];

    AddRoundKey(State,Nr);

    for(Round=(Nr-1) ; Round>0 ; Round--){
        InvShiftRows(State);
        InvSubBytes(State);
        AddRoundKey(State,Round);

		// KMS V6
		if(Round == 4){
			State[0] ^= 0x73;
		}else if(Round == 6){
			State[0] ^= 0x09;
		}else if(Round == 8){
			State[0] ^= 0xE4;
		}

        InvMixColumns(State);
    };

    InvShiftRows(State);
    InvSubBytes(State);
    AddRoundKey(State,0);

    for(i=0 ; i<16 ; i++)
        pOut[i]=State[i];
};

#pragma endregion

#pragma region Initialization and Cleanup

// AES Init
DWORD AesInit(DWORD dwType, DWORD dwMode, BYTE bPadding, PBYTE pbKey, PBYTE pbIV)
{
    DWORD i,N;

    if ((dwType != AES_TYPE_128) && (dwType != AES_TYPE_192) && (dwType != AES_TYPE_256))
        return 1;
    if ((dwMode != AES_MODE_ECB) && (dwMode != AES_MODE_CBC) && (dwMode != AES_MODE_CFB) && (dwMode != AES_MODE_OFB) && (dwMode != AES_MODE_CTR))
        return 2;
    if (pbKey == NULL)
        return 3;
    if (pbIV == NULL)
        return 4;

    if (pKey != NULL){
        for(i=0 ; i<32 ; i++)
            pKey[i]=0x00;
        delete(pKey);
    };

    if (pIV != NULL){
        for(i=0 ; i<16 ; i++)
            pIV[i]=0x00;
        delete(pIV);
    };

    Type=dwType;
    Mode=dwMode;
    Padding=bPadding;
    pKey = new BYTE[32];
    Nb=4;

    switch(Type){
    case AES_TYPE_128:
        N=16;
        Nr=10;
        Nk=4;
        break;
    case AES_TYPE_192:
        N=24;
        Nr=12;
        Nk=6;
        break;
    default:
        N=32;
        Nr=14;
        Nk=8;
    };

    for(i=0 ; i<N ; i++)
        pKey[i]=pbKey[i];

    pIV = new BYTE[16];

    for(i=0 ; i<16 ; i++)
        pIV[i]=pbIV[i];

    pSubKeys = new DWORD[Nb*(Nr+1)];
    KeyExpansion();
    IsInit=true;

    return 0;
};

// AES Clear
DWORD AesClear(void)
{
    unsigned int i;

    if (!IsInit)
        return 5;

    if (pSubKeys != NULL){
        for(i=0 ; i<(Nb*(Nr+1)) ; i++)
            pSubKeys[i]=0x00000000;
        delete(pSubKeys);
    };

    pSubKeys=NULL;

    if (pKey != NULL){
        for(i=0 ; i<32 ; i++)
            pKey[i]=0x00;
        delete(pKey);
    };

    pKey=NULL;

    if (pIV != NULL){
        for(i=0 ; i<16 ; i++)
            pIV[i]=0x00;
        delete(pIV);
    };

    pIV=NULL;
    Type=AES_TYPE_128;
    Mode=AES_MODE_ECB;
    Padding=0x00;
    IsInit=false;

    return 0;
};

#pragma endregion

#pragma region Encryption

// Aes Encrypt Block
DWORD AesEncryptBlock(PBYTE PlainText, DWORD PlainTextSize, PBYTE Cipher)
{
    BYTE bIn[16];
    DWORD i,j;

    if (PlainTextSize > 16)
        return 1;

    for(i=0 ; i<PlainTextSize ; i++)
        bIn[i]=PlainText[i];

    for(j=i ; j<16 ; j++)
        bIn[j]=Padding;

    DoCipher(bIn,Cipher);

    return 0;
};

// AES Encrypt
DWORD AesEncrypt(PBYTE PlainText, DWORD PlainTextSize, PBYTE Cipher, PDWORD CipherSize)
{
    DWORD N,n;
    DWORD i,j;
    DWORD Error;
    DWORD DataLen;
    BYTE Temp[16];
    DataLen=0;
    N=PlainTextSize/16;
    n=PlainTextSize-16*N;
    (*CipherSize)=0;

    if (PlainTextSize == 0)
        return 1;

    switch(Mode){
    case AES_MODE_ECB:
        for(i=0 ; i<N ; i++){
            Error=AesEncryptBlock(PlainText+16*i,16,Cipher+16*i);

            if (Error != 0)
                return Error;

            DataLen+=16;
        };

        if (n != 0){
            Error=AesEncryptBlock(PlainText+16*N,n,Cipher+16*N);

            if (Error != 0)
                return Error;

            DataLen+=16;
        };

        (*CipherSize)=DataLen;

        break;
    case AES_MODE_CBC:
        for(i=0 ; i<N ; i++){

            for(j=0 ; j<16 ; j++){
                if (i == 0)
                    Temp[j]=(pIV[j]^PlainText[j]);
                else
                    Temp[j]=(Cipher[16*(i-1)+j]^PlainText[16*i+j]);
            };

            Error=AesEncryptBlock(Temp,16,Cipher+16*i);

            if (Error != 0)
                return Error;

            DataLen+=16;
        };

        if (n != 0){

            for(j=0 ; j<n ; j++){
                if (N == 0)
                    Temp[j]=(pIV[j]^PlainText[j]);
                else
                    Temp[j]=(Cipher[16*(N-1)+j]^PlainText[16*N+j]);
            };

            for(j=n ; j<16 ; j++){
                if (N == 0)
                    Temp[j]=(pIV[j]^Padding);
                else
                    Temp[j]=(Cipher[16*(N-1)+j]^Padding);
            };

            Error=AesEncryptBlock(Temp,16,Cipher+16*N);

            if (Error != 0)
                return Error;

            DataLen+=16;
        };

        (*CipherSize)=DataLen;

        break;
    case AES_MODE_CFB:
        for(i=0 ; i<N ; i++){
            if (i == 0)
                Error=AesEncryptBlock(pIV,16,Temp);
            else
                Error=AesEncryptBlock(Cipher+16*(i-1),16,Temp);

            if (Error != 0)
                return Error;

            for(j=0 ; j<16 ; j++)
                Cipher[16*i+j]=Temp[j]^PlainText[16*i+j];

            DataLen+=16;
        };

        if (n != 0){
            if (i == 0)
                Error=AesEncryptBlock(pIV,16,Temp);
            else
                Error=AesEncryptBlock(Cipher+16*(i-1),16,Temp);

            if (Error != 0)
                return Error;

            for(j=0 ; j<n ; j++)
                Cipher[16*i+j]=Temp[j]^PlainText[16*i+j];

            for(j=n ; j<16 ; j++)
                Cipher[16*i+j]=Temp[j]^Padding;

            DataLen+=16;
        };

        (*CipherSize)=DataLen;

        break;
    case AES_MODE_OFB:
        for(i=0 ; i<N ; i++){
            if (i == 0)
                Error=AesEncryptBlock(pIV,16,Temp);
            else
                Error=AesEncryptBlock(Temp,16,Temp);

            if (Error != 0)
                return Error;

            for(j=0 ; j<16 ; j++)
                Cipher[16*i+j]=Temp[j]^PlainText[16*i+j];

            DataLen+=16;
        };

        if (n != 0){
            if (i == 0)
                Error=AesEncryptBlock(pIV,16,Temp);
            else
                Error=AesEncryptBlock(Temp,16,Temp);

            if (Error != 0)
                return Error;

            for(j=0 ; j<n ; j++)
                Cipher[16*i+j]=Temp[j]^PlainText[16*i+j];

            for(j=n ; j<16 ; j++)
                Cipher[16*i+j]=Temp[j]^Padding;

            DataLen+=16;
        };

        (*CipherSize)=DataLen;

        break;
    default:
        return 1;
    };

    return 0;
};

// Encrypt Message
void EncryptMessage(int MessageSize, PBYTE Message)
{
    PBYTE p;
    DWORD q;

    p = new BYTE[MessageSize];
    memcpy(p, Message, MessageSize);

    AesEncrypt(p, MessageSize, Message, &q);

    delete[] p;
};

#pragma endregion

#pragma region Decryption

// Aes Decrypt Block
DWORD AesDecryptBlock(PBYTE Cipher, PBYTE PlainText)
{
    DoInvCipher(Cipher,PlainText);

    return 0;
};

// AES Decrypt
DWORD AesDecrypt(PBYTE Cipher, DWORD CipherSize, PBYTE PlainText, PDWORD PlainTextSize)
{
    DWORD N,n;
    DWORD i,j;
    DWORD Error;
    BYTE Temp[16];
    N=CipherSize/16;
    n=CipherSize-16*N;
    (*PlainTextSize)=0;

    if (CipherSize == 0)
        return 1;
    if (n != 0)
        return 1;

    switch(Mode){
    case AES_MODE_ECB:
        for(i=0 ; i<N ; i++){
            Error=AesDecryptBlock(Cipher+16*i,PlainText+16*i);

            if (Error != 0)
                return Error;
        };

        (*PlainTextSize)=CipherSize;

        break;
    case AES_MODE_CBC:
        for(i=0 ; i<N ; i++){
            Error=AesDecryptBlock(Cipher+16*i,Temp);

            if (Error != 0)
                return Error;

            for(j=0 ; j<16 ; j++){
                if (i == 0)
                    PlainText[16*i+j]=(pIV[j]^Temp[j]);
                else
                    PlainText[16*i+j]=(Cipher[16*(i-1)+j]^Temp[j]);
            };
        };

        (*PlainTextSize)=CipherSize;

        break;
    case AES_MODE_CFB:
        for(i=0 ; i<N ; i++){
            if (i == 0)
                Error=AesEncryptBlock(pIV,16,Temp);
            else
                Error=AesEncryptBlock(Cipher+16*(i-1),16,Temp);

            if (Error != 0)
                return Error;

            for(j=0 ; j<16 ; j++)
                PlainText[16*i+j]=Temp[j]^Cipher[16*i+j];
        };

        (*PlainTextSize)=CipherSize;

        break;
    case AES_MODE_OFB:
        for(i=0 ; i<N ; i++){
            if (i == 0)
                Error=AesEncryptBlock(pIV,16,Temp);
            else
                Error=AesEncryptBlock(Temp,16,Temp);

            if (Error != 0) return Error;

            for(j=0 ; j<16 ; j++)
                PlainText[16*i+j]=Temp[j]^Cipher[16*i+j];
        };

        (*PlainTextSize)=CipherSize;

        break;
    default:
        return 1;
    };

    return 0;
};

// Decrypt Message
void DecryptMessage(int MessageSize, PBYTE Message)
{
    PBYTE p;
    DWORD q;

    p = new BYTE[MessageSize];
    memcpy(p, Message, MessageSize);

    AesDecrypt(p, MessageSize, Message, &q);

    delete[] p;
};

#pragma endregion