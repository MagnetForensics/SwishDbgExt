/*++
    MoonSols Incident Response & Digital Forensics Debugging Extension

    Copyright (C) 2014 MoonSols Ltd.
    Copyright (C) 2014 Matthieu Suiche (@msuiche)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

Module Name:

    - Credentials.h

Abstract:

    - http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx

    Thanks to Benjamin Delpy (@mimikatz) for open sourcing his project.


Environment:

    - User mode

Revision History:

    - Matthieu Suiche

    --*/

#include "SwishDbgExt.h"

#ifndef __CREDENTIALS_H__
#define __CREDENTIALS_H__

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#endif

#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define RtlEqualLuid(L1, L2) (((L1)->LowPart == (L2)->LowPart) && ((L1)->HighPart == (L2)->HighPart))

#define KUHL_SEKURLSA_CREDS_DISPLAY_RAW 0x00000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_LINE 0x00000001
#define KUHL_SEKURLSA_CREDS_DISPLAY_NEWLINE 0x00000002

#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL 0x08000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY 0x01000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIALKEY 0x02000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL_MASK 0x07000000

#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDMANPASS 0x00400000
#define KUHL_SEKURLSA_CREDS_DISPLAY_PINCODE 0x00800000

#define KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT 0x10000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_WPASSONLY 0x20000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN 0x40000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_SSP 0x80000000

#define LM_NTLM_HASH_LENGTH 16
#define SHA_DIGEST_LENGTH 20

typedef struct _CREDMAN_INFOS {
    ULONG structSize;
    ULONG offsetFLink;
    ULONG offsetUsername;
    ULONG offsetDomain;
    ULONG offsetCbPassword;
    ULONG offsetPassword;
} CREDMAN_INFOS, *PCREDMAN_INFOS;

template <class T>
struct LIST_ENTRY_T
{
    T Flink;
    T Blink;
};

template <class T>
struct UNICODE_STRING_T
{
    union
    {
        struct
        {
            WORD Length;
            WORD MaximumLength;
        };
        T dummy;
    };
    T Buffer;
};

template <class T>
struct ANSI_STRING_T
{
    USHORT Length;
    USHORT MaximumLength;
    T Buffer;
};

typedef struct ANSI_STRING_T<ULONG32> ANSI_STRING_X86, *PANSI_STRING_X86;
typedef struct ANSI_STRING_T<ULONG64> ANSI_STRING_X6, *PANSI_STRING_X64;

#if 0
typedef struct _MSV1_0_PRIMARY_CREDENTIAL {
    LSA_UNICODE_STRING LogonDomainName;
    LSA_UNICODE_STRING UserName;
    BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
    BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
    BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
    BOOLEAN isNtOwfPassword;
    BOOLEAN isLmOwfPassword;
    BOOLEAN isShaOwPassword;
    /* buffer */
} MSV1_0_PRIMARY_CREDENTIAL, *PMSV1_0_PRIMARY_CREDENTIAL;
#endif

typedef struct _RPCE_COMMON_TYPE_HEADER {
    UCHAR Version;
    UCHAR Endianness;
    USHORT CommonHeaderLength;
    ULONG Filler;
} RPCE_COMMON_TYPE_HEADER, *PRPCE_COMMON_TYPE_HEADER;

typedef struct _RPCE_PRIVATE_HEADER {
    ULONG ObjectBufferLength;
    ULONG Filler;
} RPCE_PRIVATE_HEADER, *PRPCE_PRIVATE_HEADER;

typedef ULONG32 RPCEID;

typedef struct _MARSHALL_KEY {
    DWORD unkId;
    USHORT unk0;
    USHORT length;
    RPCEID ElementId;
} MARSHALL_KEY, *PMARSHALL_KEY;

typedef struct _RPCE_CREDENTIAL_KEYCREDENTIAL {
    RPCE_COMMON_TYPE_HEADER typeHeader;
    RPCE_PRIVATE_HEADER privateHeader;
    RPCEID RootElementId;
    DWORD unk0;
    DWORD unk1;
    MARSHALL_KEY key[ANYSIZE_ARRAY];
} RPCE_CREDENTIAL_KEYCREDENTIAL, *PRPCE_CREDENTIAL_KEYCREDENTIAL;

template <class T>
struct KIWI_GENERIC_PRIMARY_CREDENTIAL_T
{
    UNICODE_STRING_T<T> UserName;
    UNICODE_STRING_T<T> Domaine;
    UNICODE_STRING_T<T> Password;
};

typedef KIWI_GENERIC_PRIMARY_CREDENTIAL_T<ULONG32> KIWI_GENERIC_PRIMARY_CREDENTIAL_X86, *PKIWI_GENERIC_PRIMARY_CREDENTIAL_X86;
typedef KIWI_GENERIC_PRIMARY_CREDENTIAL_T<ULONG64> KIWI_GENERIC_PRIMARY_CREDENTIAL_X64, *PKIWI_GENERIC_PRIMARY_CREDENTIAL_X64;

typedef struct _KUHL_M_SEKURLSA_ENUM_HELPER {
    ULONG tailleStruct;
    ULONG offsetToLuid;
    ULONG offsetToLogonType;
    ULONG offsetToSession;
    ULONG offsetToUsername;
    ULONG offsetToDomain;
    ULONG offsetToCredentials;
    ULONG offsetToPSid;
    ULONG offsetToCredentialManager;
} KUHL_M_SEKURLSA_ENUM_HELPER, *PKUHL_M_SEKURLSA_ENUM_HELPER;

typedef struct _KIWI_BASIC_SECURITY_LOGON_SESSION_DATA {
    LUID LogonId;
    ULONG64 UserName;
    ULONG64 LogonDomain;
    ULONG LogonType;
    ULONG Session;
    ULONG64 pCredentials;
    ULONG64 pSid;
    ULONG64 pCredentialManager;
} KIWI_BASIC_SECURITY_LOGON_SESSION_DATA, *PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA;
typedef void (CALLBACK * PKUHL_M_SEKURLSA_PACKAGE_CALLBACK) (_In_ ULONG64 pKerbGlobalLogonSessionTable,_In_ PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);

typedef struct _KUHL_M_SEKURLSA_PACKAGE {
    const char * name;
    const char * symbolName;
    ULONG64 symbolPtr;
    const PKUHL_M_SEKURLSA_PACKAGE_CALLBACK callback;
} KUHL_M_SEKURLSA_PACKAGE, *PKUHL_M_SEKURLSA_PACKAGE;

typedef NTSTATUS(WINAPI * PBCRYPT_OPEN_ALGORITHM_PROVIDER)  (__out BCRYPT_ALG_HANDLE  *phAlgorithm, __in LPCWSTR pszAlgId, __in_opt LPCWSTR pszImplementation, __in ULONG dwFlags);
typedef NTSTATUS(WINAPI * PBCRYPT_SET_PROPERTY) (__inout BCRYPT_HANDLE hObject, __in LPCWSTR pszProperty, __in_bcount(cbInput) PUCHAR pbInput, __in ULONG cbInput, __in ULONG dwFlags);
typedef NTSTATUS(WINAPI * PBCRYPT_GET_PROPERTY) (__in BCRYPT_HANDLE hObject, __in LPCWSTR pszProperty, __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR pbOutput, __in ULONG cbOutput, __out ULONG *pcbResult, __in ULONG dwFlags);
typedef NTSTATUS(WINAPI * PBCRYPT_GENERATE_SYMMETRIC_KEY) (__inout BCRYPT_ALG_HANDLE hAlgorithm, __out BCRYPT_KEY_HANDLE *phKey, __out_bcount_full_opt(cbKeyObject) PUCHAR pbKeyObject, __in ULONG cbKeyObject, __in_bcount(cbSecret) PUCHAR pbSecret, __in ULONG cbSecret, __in ULONG dwFlags);
typedef NTSTATUS(WINAPI * PBCRYPT_DESTROY_KEY) (__inout BCRYPT_KEY_HANDLE hKey);
typedef NTSTATUS(WINAPI * PBCRYPT_CLOSE_ALGORITHM_PROVIDER) (__inout BCRYPT_ALG_HANDLE hAlgorithm, __in ULONG dwFlags);
typedef NTSTATUS(WINAPI * PBCRYPT_ENCRYPT) (__inout BCRYPT_KEY_HANDLE hKey, __in_bcount_opt(cbInput) PUCHAR pbInput, __in ULONG cbInput, __in_opt VOID *pPaddingInfo, __inout_bcount_opt(cbIV) PUCHAR pbIV, __in ULONG cbIV, __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR pbOutput, __in ULONG cbOutput, __out ULONG *pcbResult, __in ULONG dwFlags);

typedef struct _KIWI_HARD_KEY {
    ULONG cbSecret;
    BYTE data[ANYSIZE_ARRAY]; // etc...
} KIWI_HARD_KEY, *PKIWI_HARD_KEY;

#define KULL_M_WIN_BUILD_XP 2600
#define KULL_M_WIN_BUILD_2K3 3790
#define KULL_M_WIN_BUILD_VISTA 6000
#define KULL_M_WIN_BUILD_7 7600
#define KULL_M_WIN_BUILD_8 9200
#define KULL_M_WIN_BUILD_BLUE 9600

#define KULL_M_WIN_MIN_BUILD_XP 2500
#define KULL_M_WIN_MIN_BUILD_2K3 3000
#define KULL_M_WIN_MIN_BUILD_VISTA 6000
#define KULL_M_WIN_MIN_BUILD_7 7000
#define KULL_M_WIN_MIN_BUILD_8 8000
#define KULL_M_WIN_MIN_BUILD_BLUE 9400

//
// 32bits
//
template <class T>
struct _KIWI_BCRYPT_KEY_T {
    ULONG size;
    ULONG tag; // 'MSSK'
    ULONG type;
    ULONG unk0;
    ULONG unk1;
    ULONG unk2;
    KIWI_HARD_KEY hardkey;
};

template <class T>
struct _KIWI_BCRYPT_KEY8_T {
    ULONG size;
    ULONG tag; // 'MSSK'
    ULONG type;
    ULONG unk0;
    ULONG unk1;
    ULONG unk2;
    ULONG unk3;
    T unk4; // before, align_In_x64
    KIWI_HARD_KEY hardkey;
};

template <class T>
struct _KIWI_BCRYPT_KEY81_T {
    ULONG size;
    ULONG tag; // 'MSSK'
    ULONG type;
    ULONG unk0;
    ULONG unk1;
    ULONG unk2;
    ULONG unk3;
    ULONG unk4;
    T unk5; // before, align_In_x64
    ULONG unk6;
    ULONG unk7;
    ULONG unk8;
    ULONG unk9;
    KIWI_HARD_KEY hardkey;
};

template <class T>
struct _KIWI_BCRYPT_HANDLE_KEY_T {
    ULONG size;
    ULONG tag; // 'UUUR'
    T hAlgorithm;
    T key; // PKIWI_BCRYPT_KEY
    T unk0;
};

typedef struct _BCRYPT_GEN_KEY {
    BCRYPT_ALG_HANDLE hProvider; // BCRYPT_ALG_HANDLE
    BCRYPT_KEY_HANDLE hKey; // BCRYPT_KEY_HANDLE
    PUCHAR pKey; // PUCHAR
    ULONG cbKey;
} BCRYPT_GEN_KEY, *PBCRYPT_GEN_KEY;

typedef struct _KIWI_BCRYPT_KEY_T<ULONG32> KIWI_BCRYPT_KEY_X86, *PKIWI_BCRYPT_KEY_X86;
typedef struct _KIWI_BCRYPT_KEY8_T<ULONG32> KIWI_BCRYPT_KEY8_X86, *PKIWI_BCRYPT_KEY8_X86;
typedef struct _KIWI_BCRYPT_KEY81_T<ULONG32> KIWI_BCRYPT_KEY81_X86, *PKIWI_BCRYPT_KEY81_X86;
typedef struct _KIWI_BCRYPT_HANDLE_KEY_T<ULONG32> KIWI_BCRYPT_HANDLE_KEY_X86, *PKIWI_BCRYPT_HANDLE_KEY_X86;

typedef struct _KIWI_BCRYPT_KEY_T<ULONG64> KIWI_BCRYPT_KEY_X64, *PKIWI_BCRYPT_KEY_X64;
typedef struct _KIWI_BCRYPT_KEY8_T<ULONG64> KIWI_BCRYPT_KEY8_X64, *PKIWI_BCRYPT_KEY8_X64;
typedef struct _KIWI_BCRYPT_KEY81_T<ULONG64> KIWI_BCRYPT_KEY81_X64, *PKIWI_BCRYPT_KEY81_X64;
typedef struct _KIWI_BCRYPT_HANDLE_KEY_T<ULONG64> KIWI_BCRYPT_HANDLE_KEY_X64, *PKIWI_BCRYPT_HANDLE_KEY_X64;
//
// 32-bits
//

template <class T>
struct _KIWI_MSV1_0_LIST_60_T {
    LIST_ENTRY_T<T> List;
    T unk0;
    ULONG unk1;
    T unk2;
    ULONG unk3;
    ULONG unk4;
    ULONG unk5;
    T hSemaphore6;
    T unk7;
    T hSemaphore8;
    T unk9;
    T unk10;
    ULONG unk11;
    ULONG unk12;
    T unk13;
    LUID LocallyUniqueIdentifier;
    LUID SecondaryLocallyUniqueIdentifier;
    UNICODE_STRING_T<T> UserName;
    UNICODE_STRING_T<T >Domaine;
    T unk14;
    T unk15;
    T  pSid;
    ULONG LogonType;
    ULONG Session;
    LARGE_INTEGER LogonTime; // autoalign x86
    UNICODE_STRING_T<T> LogonServer;
    T Credentials; // PKIWI_MSV1_0_CREDENTIALS_
    ULONG unk19;
    T unk20;
    T unk21;
    T unk22;
    ULONG unk23;
    T CredentialManager;
};

template <class T>
struct _KIWI_MSV1_0_LIST_61_T {
    LIST_ENTRY_T<T> List;
    T unk0;
    ULONG unk1;
    T unk2;
    ULONG unk3;
    ULONG unk4;
    ULONG unk5;
    T hSemaphore6;
    T unk7;
    T hSemaphore8;
    T unk9;
    T unk10;
    ULONG unk11;
    ULONG unk12;
    T unk13;
    LUID LocallyUniqueIdentifier;
    LUID SecondaryLocallyUniqueIdentifier;
    UNICODE_STRING_T<T> UserName;
    UNICODE_STRING_T<T> Domaine;
    T unk14;
    T unk15;
    T  pSid;
    ULONG LogonType;
    ULONG Session;
    LARGE_INTEGER LogonTime; // autoalign x86
    UNICODE_STRING_T<T> LogonServer;
    T Credentials; // PKIWI_MSV1_0_CREDENTIALS
    T unk19;
    T unk20;
    T unk21;
    ULONG unk22;
    T CredentialManager;
};

template <class T>
struct _KIWI_MSV1_0_LIST_62_T {
    LIST_ENTRY_T<T> List;
    T unk0;
    ULONG unk1;
    T unk2;
    ULONG unk3;
    ULONG unk4;
    ULONG unk5;
    T hSemaphore6;
    T unk7;
    T hSemaphore8;
    T unk9;
    T unk10;
    ULONG unk11;
    ULONG unk12;
    T unk13;
    LUID LocallyUniqueIdentifier;
    LUID SecondaryLocallyUniqueIdentifier;
    UNICODE_STRING_T<T> UserName;
    UNICODE_STRING_T<T> Domaine;
    T unk14;
    T unk15;
    UNICODE_STRING_T<T> Type;
    T  pSid;
    ULONG LogonType;
    T unk18;
    ULONG Session;
    LARGE_INTEGER LogonTime; // autoalign x86
    UNICODE_STRING_T<T> LogonServer;
    T Credentials; // PKIWI_MSV1_0_CREDENTIALS
    T unk19;
    T unk20;
    T unk21;
    ULONG unk22;
    ULONG unk23;
    ULONG unk24;
    ULONG unk25;
    ULONG unk26;
    T unk27;
    T unk28;
    T unk29;
    T CredentialManager;
};

template <class T>
struct _KIWI_MSV1_0_LIST_63_T {
    LIST_ENTRY_T<T> List;
    T unk0; // unk_2C0AC8
    ULONG unk1; // 0FFFFFFFFh
    T unk2; // 0
    ULONG unk3; // 0
    ULONG unk4; // 0
    ULONG unk5; // 0A0007D0h
    T hSemaphore6; // 0F9Ch HANDLE
    T unk7; // 0
    T hSemaphore8; // 0FB8h HANDLE
    T unk9; // 0
    T unk10; // 0
    ULONG unk11; // 0
    ULONG unk12; // 0 
    T unk13; // unk_2C0A28
    LUID LocallyUniqueIdentifier;
    LUID SecondaryLocallyUniqueIdentifier;
    BYTE waza[12]; /// to do (maybe align)
    UNICODE_STRING_T<T> UserName;
    UNICODE_STRING_T<T> Domaine;
    T unk14;
    T unk15;
    UNICODE_STRING_T<T> Type;
    T  pSid; // PSID
    ULONG LogonType;
    T unk18;
    ULONG Session;
    LARGE_INTEGER LogonTime; // autoalign x86
    UNICODE_STRING_T<T> LogonServer;
    T Credentials; // PKIWI_MSV1_0_CREDENTIALS
    T unk19;
    T unk20;
    T unk21;
    ULONG unk22;
    ULONG unk23;
    ULONG unk24;
    ULONG unk25;
    ULONG unk26;
    T unk27;
    T unk28;
    T unk29;
    T CredentialManager;
};

typedef struct _KIWI_MSV1_0_LIST_60_T<ULONG32> KIWI_MSV1_0_LIST_60_X86, *PKIWI_MSV1_0_LIST_60_X86;
typedef struct _KIWI_MSV1_0_LIST_61_T<ULONG32> KIWI_MSV1_0_LIST_61_X86, *PKIWI_MSV1_0_LIST_61_X86;
typedef struct _KIWI_MSV1_0_LIST_62_T<ULONG32> KIWI_MSV1_0_LIST_62_X86, *PKIWI_MSV1_0_LIST_62_X86;
typedef struct _KIWI_MSV1_0_LIST_63_T<ULONG32> KIWI_MSV1_0_LIST_63_X86, *PKIWI_MSV1_0_LIST_63_X86;

typedef struct _KIWI_MSV1_0_LIST_60_T<ULONG64> KIWI_MSV1_0_LIST_60_X64, *PKIWI_MSV1_0_LIST_60_X64;
typedef struct _KIWI_MSV1_0_LIST_61_T<ULONG64> KIWI_MSV1_0_LIST_61_X64, *PKIWI_MSV1_0_LIST_61_X64;
typedef struct _KIWI_MSV1_0_LIST_62_T<ULONG64> KIWI_MSV1_0_LIST_62_X64, *PKIWI_MSV1_0_LIST_62_X64;
typedef struct _KIWI_MSV1_0_LIST_63_T<ULONG64> KIWI_MSV1_0_LIST_63_X64, *PKIWI_MSV1_0_LIST_63_X64;

//
// 32-bits
//
template <class T>
struct KIWI_MSV1_0_PRIMARY_CREDENTIALS_T {
    T next;
    ANSI_STRING_T<T> Primary;
    UNICODE_STRING_T<T> Credentials;
};

template <class T>
struct KIWI_MSV1_0_CREDENTIALS_T {
    T next;
    DWORD AuthenticationPackageId;
    T PrimaryCredentials;
};

typedef struct KIWI_MSV1_0_PRIMARY_CREDENTIALS_T<ULONG32> KIWI_MSV1_0_PRIMARY_CREDENTIALS_X86, *PKIWI_MSV1_0_PRIMARY_CREDENTIALS_X86;
typedef struct KIWI_MSV1_0_PRIMARY_CREDENTIALS_T<ULONG64> KIWI_MSV1_0_PRIMARY_CREDENTIALS_X64, *PKIWI_MSV1_0_PRIMARY_CREDENTIALS_X64;

typedef struct KIWI_MSV1_0_CREDENTIALS_T<ULONG32> KIWI_MSV1_0_CREDENTIALS_X86, *PKIWI_MSV1_0_CREDENTIALS_X86;
typedef struct KIWI_MSV1_0_CREDENTIALS_T<ULONG64> KIWI_MSV1_0_CREDENTIALS_X64, *PKIWI_MSV1_0_CREDENTIALS_X64;

template <class T>
struct KIWI_TS_CREDENTIAL_T {
    BYTE unk0[64];
    LUID LocallyUniqueIdentifier;
    T unk1;
    T unk2;
    T pTsPrimary; //PKIWI_TS_PRIMARY_CREDENTIAL
};

typedef struct KIWI_TS_CREDENTIAL_T<ULONG32> KIWI_TS_CREDENTIAL_X86, *PKIWI_TS_CREDENTIAL_X86;
typedef struct KIWI_TS_CREDENTIAL_T<ULONG64> KIWI_TS_CREDENTIAL_X64, *PKIWI_TS_CREDENTIAL_X64;

template <class T>
struct KIWI_TS_PRIMARY_CREDENTIAL_T {
    T unk0; // lock ?
    KIWI_GENERIC_PRIMARY_CREDENTIAL_T<T> credentials;
};

typedef struct KIWI_TS_PRIMARY_CREDENTIAL_T<ULONG32> KIWI_TS_PRIMARY_CREDENTIAL_X86, *PKIWI_TS_PRIMARY_CREDENTIAL_X86;
typedef struct KIWI_TS_PRIMARY_CREDENTIAL_T<ULONG64> KIWI_TS_PRIMARY_CREDENTIAL_X64, *PKIWI_TS_PRIMARY_CREDENTIAL_X64;

//
// 32bits
//
template <class T>
struct KIWI_CREDMAN_LIST_ENTRY_60_T {
    ULONG cbEncPassword;
    T encPassword; // PWSTR
    ULONG unk0;
    ULONG unk1;
    T unk2;
    T unk3;
    T UserName; // PWSTR
    ULONG cbUserName;
    LIST_ENTRY_T<T> List; // struct _KIWI_CREDMAN_LIST_ENTRY_X86 *
    UNICODE_STRING_T<T> type;
    T unk5; // PVOID
    UNICODE_STRING_T<T> server1;
    T unk6;
    T unk7;
    T unk8;
    T unk9;
    T unk10;
    UNICODE_STRING_T<T> user;
    ULONG unk11;
    UNICODE_STRING_T<T> server2;
};

template <class T>
struct KIWI_CREDMAN_LIST_ENTRY_T {
    ULONG cbEncPassword;
    T encPassword; // PWSTR
    ULONG unk0;
    ULONG unk1;
    T unk2; // PVOID
    T unk3;
    T UserName; // LPWSTR
    ULONG cbUserName;
    LIST_ENTRY_T<T> List1; // _KIWI_CREDMAN_LIST_ENTRY *
    LIST_ENTRY_T<T> List2;
    UNICODE_STRING_T<T> type;
    T unk5;
    UNICODE_STRING_T<T> server1;
    T unk6;
    T unk7;
    T unk8;
    T unk9;
    T unk10;
    UNICODE_STRING_T<T> user;
    ULONG unk11;
    UNICODE_STRING_T<T> server2;
};

template <class T>
struct KIWI_CREDMAN_LIST_STARTER_T {
    ULONG unk0;
    T start; // PKIWI_CREDMAN_LIST_ENTRY
    //...
};

template <class T>
struct KIWI_CREDMAN_SET_LIST_ENTRY_T {
    LIST_ENTRY_T<T> List; // _KIWI_CREDMAN_SET_LIST_ENTRY_X86
    ULONG unk0;
    T list1; // PKIWI_CREDMAN_LIST_STARTER_X86
    T list2; // PKIWI_CREDMAN_LIST_STARTER_X86
    // ...
};

typedef struct KIWI_CREDMAN_LIST_ENTRY_60_T<ULONG32> KIWI_CREDMAN_LIST_ENTRY_60_X86, *PKIWI_CREDMAN_LIST_ENTRY_60_X86;
typedef struct KIWI_CREDMAN_LIST_ENTRY_T<ULONG32> KIWI_CREDMAN_LIST_ENTRY_X86, *PKIWI_CREDMAN_LIST_ENTRY_X86;
typedef struct KIWI_CREDMAN_LIST_STARTER_T<ULONG32> KIWI_CREDMAN_LIST_STARTER_X86, *PKIWI_CREDMAN_LIST_STARTER_X86;
typedef struct KIWI_CREDMAN_SET_LIST_ENTRY_T<ULONG32> KIWI_CREDMAN_SET_LIST_ENTRY_X86, *PKIWI_CREDMAN_SET_LIST_ENTRY_X86;

typedef struct KIWI_CREDMAN_LIST_ENTRY_60_T<ULONG64> KIWI_CREDMAN_LIST_ENTRY_60_X64, *PKIWI_CREDMAN_LIST_ENTRY_60_X64;
typedef struct KIWI_CREDMAN_LIST_ENTRY_T<ULONG64> KIWI_CREDMAN_LIST_ENTRY_X64, *PKIWI_CREDMAN_LIST_ENTRY_X64;
typedef struct KIWI_CREDMAN_LIST_STARTER_T<ULONG64> KIWI_CREDMAN_LIST_STARTER_X64, *PKIWI_CREDMAN_LIST_STARTER_X64;
typedef struct KIWI_CREDMAN_SET_LIST_ENTRY_T<ULONG64> KIWI_CREDMAN_SET_LIST_ENTRY_X64, *PKIWI_CREDMAN_SET_LIST_ENTRY_X64;

void
Mimikatz(
);
#endif