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

    - Credentials.cpp

Abstract:

    - http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx

    - Thanks to Benjamin Delpy (@mimikatz) for open sourcing his project.

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#include "MoonSolsDbgExt.h"

#include <bcrypt.h>
// #include <ntstatus.h>

#define SECURITY_WIN32
#include <ntsecapi.h>
#include <sspi.h>
#include <sddl.h>
#include <wincred.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>

// ULONG g_ProcessorType;
// ULONG g_Ext->m_Machine, g_Major, g_Ext->m_Minor, g_ServicePackNumber;

HMODULE kuhl_m_sekurlsa_nt6_hBCrypt = NULL;

PBCRYPT_OPEN_ALGORITHM_PROVIDER K_BCryptOpenAlgorithmProvider = NULL;
PBCRYPT_SET_PROPERTY K_BCryptSetProperty = NULL;
PBCRYPT_GET_PROPERTY K_BCryptGetProperty = NULL;
PBCRYPT_GENERATE_SYMMETRIC_KEY K_BCryptGenerateSymmetricKey = NULL;
PBCRYPT_ENCRYPT	K_BCryptEncrypt = NULL, K_BCryptDecrypt = NULL;
PBCRYPT_DESTROY_KEY K_BCryptDestroyKey = NULL;
PBCRYPT_CLOSE_ALGORITHM_PROVIDER K_BCryptCloseAlgorithmProvider = NULL;

BCRYPT_GEN_KEY k3Des, kAes;
BYTE InitializationVector[16];

NTSTATUS kuhl_m_sekurlsa_nt6_KeyInit = STATUS_NOT_FOUND;

BOOL kull_m_string_getDbgUnicodeString(
    IN PUNICODE_STRING string
)
{
    BOOL status = FALSE;
    ULONG_PTR buffer = (ULONG_PTR)string->Buffer;
    string->Buffer = NULL;
    if (buffer && string->MaximumLength)
    {
        if (string->Buffer = (PWSTR)LocalAlloc(LPTR, string->MaximumLength))
        {
            if (!(status = ReadMemory(buffer, string->Buffer, string->MaximumLength, NULL)))
            {
                LocalFree(string->Buffer);
                string->Buffer = NULL;
            }
        }
    }
    return status;
}

VOID WINAPI kuhl_m_sekurlsa_nt6_LsaUnprotectMemory(IN PVOID Buffer, IN ULONG BufferSize)
{
    BCRYPT_KEY_HANDLE *hKey;
    BYTE LocalInitializationVector[16];
    ULONG cbIV, cbResult;
    RtlCopyMemory(LocalInitializationVector, InitializationVector, sizeof(InitializationVector));

    if (BufferSize % 8)
    {
        hKey = &kAes.hKey;
        cbIV = sizeof(InitializationVector);
    }
    else
    {
        hKey = &k3Des.hKey;
        cbIV = sizeof(InitializationVector) / 2;
    }

    K_BCryptDecrypt(*hKey, (PUCHAR)Buffer, BufferSize, 0, LocalInitializationVector, cbIV, (PUCHAR)Buffer, BufferSize, &cbResult, 0);
}

void kuhl_m_sekurlsa_utils_NlpMakeRelativeOrAbsoluteString(
    PVOID BaseAddress,
    PLSA_UNICODE_STRING String,
    BOOL relative
)
{
    if (String->Buffer)
        String->Buffer = (PWSTR)((ULONG_PTR)(String->Buffer) + ((relative ? -1 : 1) * (ULONG_PTR)(BaseAddress)));
}

const char * PRINTF_TYPES[] =
{
    "%02x", // WPRINTF_HEX_SHORT
    "%02x ", // WPRINTF_HEX_SPACE
    "0x%02x, ", // WPRINTF_HEX_C
    "\\x%02x", // WPRINTF_HEX_PYTHON
};

void kull_m_string_dprintf_hex(LPCVOID lpData, DWORD cbData, DWORD flags)
{
    DWORD i;
    const char * pType = PRINTF_TYPES[flags & 0x0000000f];
    for (i = 0; i < cbData; i++)
        g_Ext->Dml(pType, ((LPCBYTE)lpData)[i]);
}

BOOL kull_m_string_suspectUnicodeString(IN PUNICODE_STRING pUnicodeString)
{
    int unicodeTestFlags = IS_TEXT_UNICODE_ODD_LENGTH | IS_TEXT_UNICODE_STATISTICS;
    return IsTextUnicode(pUnicodeString->Buffer, pUnicodeString->Length, &unicodeTestFlags);
}

VOID kuhl_m_sekurlsa_genericKeyOutput(PMARSHALL_KEY key, PVOID * dirtyBase)
{
    switch (key->unkId)
    {
        case 0x00010002:
        case 0x00010003:
            dprintf("\n\t * NTLM     : ");
            break;
        case 0x00020002:
            dprintf("\n\t * SHA1     : ");
            break;
        case 0x00030002:
        case 0x00030003:
            dprintf("\n\t * RootKey  : ");
            break;
        case 0x00040002:
        case 0x00040003:
            dprintf("\n\t * DPAPI    : ");
            break;
        default:
            dprintf("\n\t * %08x : ", key->unkId);
    }

    kull_m_string_dprintf_hex((PBYTE)*dirtyBase + sizeof(ULONG), key->length, 0);
    *dirtyBase = (PBYTE)*dirtyBase + sizeof(ULONG)+*(PULONG)*dirtyBase;
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_msv(
    IN ULONG64 reserved,
    IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData
)
{
    // KIWI_MSV1_0_PRIMARY_CREDENTIALS_X64 primaryCredentials;

    DWORD flags;

    ULONG SizeOfMsv1_0_Credentials;
    ULONG SizeOfMsv1_0_Primary_Credentials;

    ULONG Offset_Cedentials_PrimaryCredentials;

    ULONG Offset_PrimaryCedentials_Credentials;
    ULONG Offset_PrimaryCedentials_Primary;

    if (g_Ext->m_Machine == IMAGE_FILE_MACHINE_I386)
    {
        SizeOfMsv1_0_Credentials = sizeof(KIWI_MSV1_0_CREDENTIALS_X86);
        SizeOfMsv1_0_Primary_Credentials = sizeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS_X86);

        Offset_Cedentials_PrimaryCredentials = FIELD_OFFSET(KIWI_MSV1_0_CREDENTIALS_X86, PrimaryCredentials);

        Offset_PrimaryCedentials_Credentials = FIELD_OFFSET(KIWI_MSV1_0_PRIMARY_CREDENTIALS_X86, Credentials);
        Offset_PrimaryCedentials_Primary = FIELD_OFFSET(KIWI_MSV1_0_PRIMARY_CREDENTIALS_X86, Primary);
    }
    else
    {
        SizeOfMsv1_0_Credentials = sizeof(KIWI_MSV1_0_CREDENTIALS_X64);
        SizeOfMsv1_0_Primary_Credentials = sizeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS_X64);

        Offset_Cedentials_PrimaryCredentials = FIELD_OFFSET(KIWI_MSV1_0_CREDENTIALS_X64, PrimaryCredentials);

        Offset_PrimaryCedentials_Credentials = FIELD_OFFSET(KIWI_MSV1_0_PRIMARY_CREDENTIALS_X64, Credentials);
        Offset_PrimaryCedentials_Primary = FIELD_OFFSET(KIWI_MSV1_0_PRIMARY_CREDENTIALS_X64, Primary);
    }

    ExtRemoteTypedList CredList(pData->pCredentials, "nt!_SINGLE_LIST_ENTRY", "Next");
    for (CredList.StartHead(); CredList.HasNode(); CredList.Next())
    {
        ULONG64 pPrimary;

        if (ReadPointersVirtual(1, CredList.GetNodeOffset() + Offset_Cedentials_PrimaryCredentials, &pPrimary) != S_OK) goto CleanUp;

        ExtRemoteTypedList PrimaryCredList(pPrimary, "nt!_SINGLE_LIST_ENTRY", "Next");
        for (PrimaryCredList.StartHead(); PrimaryCredList.HasNode(); PrimaryCredList.Next())
        {
            WCHAR Credential[128] = { 0 };
            WCHAR Primary[128] = { 0 };

            pPrimary = PrimaryCredList.GetNodeOffset();
#if 0
            if (g_Ext->m_Data->ReadVirtual(PrimaryCredList.GetNodeOffset(),
                                           &primaryCredentials,
                                           sizeof(primaryCredentials),
                                           NULL) != S_OK) continue;
#endif

            if (!ExtRemoteTypedEx::GetUnicodeStringEx(pPrimary + Offset_PrimaryCedentials_Credentials, (LPWSTR)&Credential, sizeof(Credential))) continue;

            if (!ExtRemoteTypedEx::GetUnicodeStringEx(pPrimary + Offset_PrimaryCedentials_Primary, (LPWSTR)&Primary, sizeof(Primary))) continue;

            // g_Ext->Dml("\n\t [%08x] %S", credentials.AuthenticationPackageId, &Primary);

            if (_wcsicmp(Primary, L"Primary") == 0) flags = KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY;
            else if (_wcsicmp(Primary, L"CredentialKeys") == 0) flags = KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIALKEY;
            else flags = 0;

            // NOT IMPLEMENTED
            // kuhl_m_sekurlsa_genericCredsOutput((PKIWI_GENERIC_PRIMARY_CREDENTIAL)&primaryCredentials.Credentials, pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL | flags);
        }
    }

CleanUp:
    return;
}

ULONG64
kuhl_m_sekurlsa_utils_pFromAVLByLuidRec(
    ULONG64 pTable,
    ULONG LUIDoffset,
    PLUID luidToFind
)
{
    ULONG64 Result = 0;

    LUID Luid;

    ExtRemoteTyped AvlTable("(nt!_RTL_AVL_TABLE *)@$extin", (ULONG64)pTable);
    ULONG64 OrderedPointer = AvlTable.Field("OrderedPointer").GetPtr();

    if (OrderedPointer)
    {
        if (g_Ext->m_Data->ReadVirtual(OrderedPointer + LUIDoffset, &Luid, sizeof(Luid), NULL) != S_OK) goto CleanUp;

        if (RtlEqualLuid(luidToFind, &Luid)) Result = OrderedPointer;
    }

    if (!Result && (pTable = AvlTable.Field("BalancedRoot").Field("LeftChild").GetPtr()))
        Result = kuhl_m_sekurlsa_utils_pFromAVLByLuidRec(pTable, LUIDoffset, luidToFind);
    if (!Result && (pTable = AvlTable.Field("BalancedRoot").Field("RightChild").GetPtr()))
        Result = kuhl_m_sekurlsa_utils_pFromAVLByLuidRec(pTable, LUIDoffset, luidToFind);

CleanUp:

    return Result;
}

ULONG64
kuhl_m_sekurlsa_utils_pFromAVLByLuid(
        ULONG64 pTable,
        ULONG LUIDoffset,
        PLUID luidToFind
)
{
    ULONG64 Result = 0;

    ExtRemoteTyped AvlTable("(nt!_RTL_AVL_TABLE *)@$extin", (ULONG64)pTable);

    ULONG64 RightChild = AvlTable.Field("BalancedRoot").Field("RightChild").GetPtr();

    Result = kuhl_m_sekurlsa_utils_pFromAVLByLuidRec(RightChild, LUIDoffset, luidToFind);

    return Result;
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_tspkg(
    IN ULONG64 pTSGlobalCredTable,
    IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData
)
{
    ULONG64 Pointer;

    ULONG LuidOffset;
    ULONG TsPrimaryOffset;
    PVOID PrimaryCredentials = NULL;
    ULONG CredentialsOffset;

    LPWSTR UserNameStr = NULL;
    LPWSTR DomainStr = NULL;
    LPWSTR PasswordStr = NULL;

    ExtRemoteTyped UserName;
    ExtRemoteTyped Domain;
    ExtRemoteTyped Password;

    if (g_Ext->m_Machine == IMAGE_FILE_MACHINE_I386)
    {
        LuidOffset = FIELD_OFFSET(KIWI_TS_CREDENTIAL_X86, LocallyUniqueIdentifier);
        TsPrimaryOffset = FIELD_OFFSET(KIWI_TS_CREDENTIAL_X86, pTsPrimary);
        CredentialsOffset = FIELD_OFFSET(KIWI_TS_PRIMARY_CREDENTIAL_X86, credentials);
    }
    else
    {
        LuidOffset = FIELD_OFFSET(KIWI_TS_CREDENTIAL_X64, LocallyUniqueIdentifier);
        TsPrimaryOffset = FIELD_OFFSET(KIWI_TS_CREDENTIAL_X64, pTsPrimary);
        CredentialsOffset = FIELD_OFFSET(KIWI_TS_PRIMARY_CREDENTIAL_X64, credentials);
    }

    Pointer = kuhl_m_sekurlsa_utils_pFromAVLByLuid(pTSGlobalCredTable, LuidOffset, &pData->LogonId);
    if (!Pointer) goto CleanUp;

    ULONG64 pTsPrimary;

    if (ReadPointersVirtual(1, Pointer + TsPrimaryOffset, &pTsPrimary) != S_OK) goto CleanUp;

    ULONG UnicodeString_Size = GetTypeSize("nt!_UNICODE_STRING");

    //
    // PRIMARY_CREDENTIALS:
    //  LSA_UNICODE_STRING_X86 Domain;
    //  LSA_UNICODE_STRING_X86 UserName;
    //  LSA_UNICODE_STRING_X86 Password;
    //

    Domain = ExtRemoteTyped("(nt!_UNICODE_STRING *)@$extin", (ULONG64)pTsPrimary + CredentialsOffset);
    UserName = ExtRemoteTyped("(nt!_UNICODE_STRING *)@$extin", (ULONG64)pTsPrimary + CredentialsOffset + (UnicodeString_Size * 1));
    Password = ExtRemoteTyped("(nt!_UNICODE_STRING *)@$extin", (ULONG64)pTsPrimary + CredentialsOffset + (UnicodeString_Size * 2));

    UserNameStr = ExtRemoteTypedEx::GetUnicodeString2(UserName);
    DomainStr = ExtRemoteTypedEx::GetUnicodeString2(Domain);

    ULONG PwdMaxLen = Password.Field("MaximumLength").GetUshort();
    PasswordStr = (LPWSTR)malloc(PwdMaxLen + sizeof(WCHAR));
    if (g_Ext->m_Data->ReadVirtual(Password.Field("Buffer").GetPtr(), PasswordStr, PwdMaxLen, NULL) != S_OK) goto CleanUp;
    kuhl_m_sekurlsa_nt6_LsaUnprotectMemory(PasswordStr, PwdMaxLen);

    USHORT PwdLen = Password.Field("Length").GetUshort();
    if (PwdLen <= PwdMaxLen)
    {
        PasswordStr[PwdLen / sizeof(PasswordStr[0])] = L'\0';
    }

    g_Ext->Dml("    User: <col fg=\"changed\">%S\\%S</col> = \"<col fg=\"emphfg\">%S</col>\" (Len=%d, MaxLen=%d)\n",
        DomainStr, UserNameStr, PasswordStr,
        PwdLen,
        PwdMaxLen);

CleanUp:
    if (UserNameStr) free(UserNameStr);
    if (DomainStr) free(DomainStr);
    if (PasswordStr) free(PasswordStr);

    return;
}

const CREDMAN_INFOS credhelper[] = {
    {
        sizeof(KIWI_CREDMAN_LIST_ENTRY_60_X86),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_60_X86, List.Flink),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_60_X86, user),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_60_X86, server2),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_60_X86, cbEncPassword),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_60_X86, encPassword),
    },
    {
        sizeof(KIWI_CREDMAN_LIST_ENTRY_X86),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_X86, List1.Flink),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_X86, user),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_X86, server2),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_X86, cbEncPassword),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_X86, encPassword),
    },
    {
        sizeof(KIWI_CREDMAN_LIST_ENTRY_60_X64),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_60_X64, List.Flink),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_60_X64, user),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_60_X64, server2),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_60_X64, cbEncPassword),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_60_X64, encPassword),
    },
    {
        sizeof(KIWI_CREDMAN_LIST_ENTRY_X64),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_X64, List1.Flink),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_X64, user),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_X64, server2),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_X64, cbEncPassword),
        FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_X64, encPassword),
    },
};

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_credman(IN ULONG64 reserved, IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
    //KIWI_CREDMAN_SET_LIST_ENTRY setList;
    //KIWI_CREDMAN_LIST_STARTER listStarter;
    DWORD nbCred = 0;
    ULONG CredOffsetIndex = 0;
    ULONG64 pCur, pRef;

    ULONG list1Offset;
    ULONG startOffset;

    LPWSTR UserNameStr = NULL;
    LPWSTR DomainStr = NULL;
    LPWSTR PasswordStr = NULL;

    if (g_Ext->m_Machine == IMAGE_FILE_MACHINE_I386)
    {
        list1Offset = FIELD_OFFSET(KIWI_CREDMAN_SET_LIST_ENTRY_X86, list1);
        startOffset = FIELD_OFFSET(KIWI_CREDMAN_LIST_STARTER_X86, start);
        CredOffsetIndex = 0;
    }
    else
    {
        list1Offset = FIELD_OFFSET(KIWI_CREDMAN_SET_LIST_ENTRY_X64, list1);
        startOffset = FIELD_OFFSET(KIWI_CREDMAN_LIST_STARTER_X64, start);
        CredOffsetIndex = 2;
    }


    if (g_Ext->m_Minor < KULL_M_WIN_BUILD_7) CredOffsetIndex += 0;
    else CredOffsetIndex += 1;

    if (!pData->pCredentialManager) goto CleanUp;

    ULONG64 list1;

    if (ReadPointersVirtual(1, pData->pCredentialManager + list1Offset, &list1) != S_OK) goto CleanUp;

    if (!list1) goto CleanUp;

    pRef = list1 + startOffset;

    ULONG64 start;
    if (ReadPointersVirtual(1, list1 + startOffset, &start) != S_OK) goto CleanUp;

    pCur = start;
    while (pCur != pRef)
    {
        pCur -= credhelper[CredOffsetIndex].offsetFLink;

        // kuhl_m_sekurlsa_genericCredsOutput(&kiwiCreds, pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_CREDMANPASS);

        //
        // PRIMARY_CREDENTIALS:
        //  LSA_UNICODE_STRING_X86 UserName;
        //  LSA_UNICODE_STRING_X86 Domaine;
        //  LSA_UNICODE_STRING_X86 Password;
        //

        ExtRemoteTyped UserName("(nt!_UNICODE_STRING *)@$extin", (ULONG64)pCur + credhelper[CredOffsetIndex].offsetUsername);
        ExtRemoteTyped Domain("(nt!_UNICODE_STRING *)@$extin", (ULONG64)pCur + credhelper[CredOffsetIndex].offsetDomain);

        if (UserNameStr) free(UserNameStr);
        if (DomainStr) free(DomainStr);
        if (PasswordStr) free(PasswordStr);

        UserNameStr = ExtRemoteTypedEx::GetUnicodeString2(UserName);
        DomainStr = ExtRemoteTypedEx::GetUnicodeString2(Domain);

        USHORT PwdMaxLen = 0;
        if (g_Ext->m_Data->ReadVirtual(pCur + credhelper[CredOffsetIndex].offsetCbPassword, &PwdMaxLen, sizeof(PwdMaxLen), NULL) != S_OK) goto CleanUp;
        ULONG64 PwdBuffer;
        if (ReadPointersVirtual(1, pCur + credhelper[CredOffsetIndex].offsetPassword, &PwdBuffer) != S_OK) goto CleanUp;
        PasswordStr = (LPWSTR)malloc(PwdMaxLen + sizeof(WCHAR));
        RtlZeroMemory(PasswordStr, PwdMaxLen);
        if (g_Ext->m_Data->ReadVirtual(PwdBuffer, PasswordStr, PwdMaxLen, NULL) != S_OK) goto CleanUp;
        kuhl_m_sekurlsa_nt6_LsaUnprotectMemory(PasswordStr, PwdMaxLen);
        PasswordStr[PwdMaxLen / sizeof(PasswordStr[0])] = L'\0';

        g_Ext->Dml("    [%08x] ", nbCred);
        g_Ext->Dml("<col fg=\"changed\">User</col> = \"<col fg=\"emphfg\">%S</col>\", "
                   "<col fg=\"changed\">Domain</col> = \"<col fg=\"emphfg\">%S</col>\", "
                   "<col fg=\"changed\">Password</col> = \"<col fg=\"emphfg\">%S</col>\" (PwdMaxLen=%d)\n",
                   UserNameStr, DomainStr, PasswordStr, PwdMaxLen);

        if (ReadPointersVirtual(1, pCur + credhelper[CredOffsetIndex].offsetFLink, &pCur) != S_OK) goto CleanUp;

        nbCred++;
    }

CleanUp :
    if (UserNameStr) free(UserNameStr);
    if (DomainStr) free(DomainStr);
    if (PasswordStr) free(PasswordStr);

    return;
}


#if 0
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_kerberos(IN ULONG_PTR pKerbGlobalLogonSessionTable, IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
    KIWI_KERBEROS_LOGON_SESSION session;
    UNICODE_STRING pinCode;
    ULONG_PTR ptr;
    if (ptr = kuhl_m_sekurlsa_utils_pFromAVLByLuid(pKerbGlobalLogonSessionTable, FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, LocallyUniqueIdentifier), pData->LogonId))
    {
        if (ReadMemory(ptr, &session, sizeof(KIWI_KERBEROS_LOGON_SESSION), NULL))
        {
            kuhl_m_sekurlsa_genericCredsOutput(&session.credentials, pData->LogonId, 0);
            if (session.pinCode)
            if (ReadMemory((ULONG_PTR)session.pinCode, &pinCode, sizeof(UNICODE_STRING), NULL))
                kuhl_m_sekurlsa_genericCredsOutput((PKIWI_GENERIC_PRIMARY_CREDENTIAL)&pinCode, pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_PINCODE);
        }
    }
    else g_Ext->Dml("KO");
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_livessp(IN ULONG_PTR pLiveGlobalLogonSessionList, IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
    KIWI_LIVESSP_LIST_ENTRY credentials;
    KIWI_LIVESSP_PRIMARY_CREDENTIAL primaryCredential;
    ULONG_PTR ptr;
    if (ptr = kuhl_m_sekurlsa_utils_pFromLinkedListByLuid(pLiveGlobalLogonSessionList, FIELD_OFFSET(KIWI_LIVESSP_LIST_ENTRY, LocallyUniqueIdentifier), pData->LogonId))
    {
        if (ReadMemory(ptr, &credentials, sizeof(KIWI_LIVESSP_LIST_ENTRY), NULL))
        if (ptr = (ULONG_PTR)credentials.suppCreds)
        if (ReadMemory(ptr, &primaryCredential, sizeof(KIWI_LIVESSP_PRIMARY_CREDENTIAL), NULL))
            kuhl_m_sekurlsa_genericCredsOutput(&primaryCredential.credentials, pData->LogonId, (NtBuildNumber != 9431) ? 0 : KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT);
    }
    else g_Ext->Dml("KO");
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_wdigest(IN ULONG_PTR pl_LogSessList, IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
    ULONG_PTR ptr;
    BYTE buffer[offsetWDigestPrimary + sizeof(KIWI_GENERIC_PRIMARY_CREDENTIAL)];
    if (ptr = kuhl_m_sekurlsa_utils_pFromLinkedListByLuid(pl_LogSessList, FIELD_OFFSET(KIWI_WDIGEST_LIST_ENTRY, LocallyUniqueIdentifier), pData->LogonId))
    {
        if (ReadMemory(ptr, buffer, sizeof(buffer), NULL))
            kuhl_m_sekurlsa_genericCredsOutput((PKIWI_GENERIC_PRIMARY_CREDENTIAL)(buffer + offsetWDigestPrimary), pData->LogonId, 0);
    }
    else g_Ext->Dml("KO");
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_ssp(IN ULONG_PTR pSspCredentialList, IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
    KIWI_SSP_CREDENTIAL_LIST_ENTRY mesCredentials;
    ULONG_PTR ptr;
    ULONG monNb = 0;
    if (ReadMemory(pSspCredentialList, &mesCredentials, sizeof(LIST_ENTRY), NULL))
    {
        ptr = (ULONG_PTR)mesCredentials.Flink;
        while (ptr != pSspCredentialList)
        {
            if (ReadMemory(ptr, &mesCredentials, sizeof(KIWI_SSP_CREDENTIAL_LIST_ENTRY), NULL))
            {
                if (RtlEqualLuid(pData->LogonId, &mesCredentials.LogonId) && (mesCredentials.credentials.UserName.Buffer || mesCredentials.credentials.Domaine.Buffer || mesCredentials.credentials.Password.Buffer))
                {
                    g_Ext->Dml("\n\t [%08x]", monNb++);
                    kuhl_m_sekurlsa_genericCredsOutput(&mesCredentials.credentials, pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_SSP | KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN);
                }
                ptr = (ULONG_PTR)mesCredentials.Flink;
            }
            else break;
        }
    }
    else g_Ext->Dml("KO");
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_masterkeys(IN ULONG_PTR pMasterKeyCacheList, IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
    KIWI_MASTERKEY_CACHE_ENTRY mesCredentials;
    ULONG_PTR ptr;
    ULONG monNb = 0;
    PBYTE buffer;

    if (ReadMemory(pMasterKeyCacheList, &mesCredentials, sizeof(LIST_ENTRY), NULL))
    {
        ptr = (ULONG_PTR)mesCredentials.Flink;
        while (ptr != pMasterKeyCacheList)
        {
            if (ReadMemory(ptr, &mesCredentials, sizeof(KIWI_MASTERKEY_CACHE_ENTRY), NULL))
            {
                if (RtlEqualLuid(pData->LogonId, &mesCredentials.LogonId))
                {
                    g_Ext->Dml("\n\t [%08x]\n\t * GUID :\t", monNb++);
                    kull_m_string_displayGUID(&mesCredentials.KeyUid);
                    g_Ext->Dml("\n\t * Time :\t"); kull_m_string_displayFileTime(&mesCredentials.insertTime);

                    if (buffer = (PBYTE)LocalAlloc(LPTR, mesCredentials.keySize))
                    {
                        if (ReadMemory(ptr + FIELD_OFFSET(KIWI_MASTERKEY_CACHE_ENTRY, key), buffer, mesCredentials.keySize, NULL))
                        {
                            kuhl_m_sekurlsa_nt6_LsaUnprotectMemory(buffer, mesCredentials.keySize);
                            g_Ext->Dml("\n\t * Key :\t"); kull_m_string_dprintf_hex(buffer, mesCredentials.keySize, 0);
                        }
                        LocalFree(buffer);
                    }
                }
                ptr = (ULONG_PTR)mesCredentials.Flink;
            }
            else break;
        }
    }
    else g_Ext->Dml("KO");
}
#endif


KUHL_M_SEKURLSA_PACKAGE packages[] = {
   // { "msv", NULL, 0, kuhl_m_sekurlsa_enum_logon_callback_msv }, // kuhl_m_sekurlsa_enum_logon_callback_msv },
   { "tspkg", "tspkg!TSGlobalCredTable", 0, kuhl_m_sekurlsa_enum_logon_callback_tspkg }, // kuhl_m_sekurlsa_enum_logon_callback_tspkg },
    //{ "wdigest", "wdigest!l_LogSessList", 0, NULL }, // kuhl_m_sekurlsa_enum_logon_callback_wdigest },
    //{ "livessp", "livessp!LiveGlobalLogonSessionList", 0, NULL }, // kuhl_m_sekurlsa_enum_logon_callback_livessp },
    //{ "kerberos", "kerberos!KerbGlobalLogonSessionTable", 0, NULL }, // kuhl_m_sekurlsa_enum_logon_callback_kerberos },
    //{ "ssp", "msv1_0!SspCredentialList", 0, NULL }, // kuhl_m_sekurlsa_enum_logon_callback_ssp },
    //{ "masterkey", "lsasrv!g_MasterKeyCacheList", 0, NULL }, // kuhl_m_sekurlsa_enum_logon_callback_masterkeys },
    //{ "masterkey", "dpapisrv!g_MasterKeyCacheList", 0, NULL }, // kuhl_m_sekurlsa_enum_logon_callback_masterkeys },
    { "credman", NULL, 0, kuhl_m_sekurlsa_enum_logon_callback_credman }, // kuhl_m_sekurlsa_enum_logon_callback_credman },
};

NTSTATUS
kuhl_m_sekurlsa_nt6_acquireKey(
    ULONG64 phKey,
    PBCRYPT_GEN_KEY pGenKey
)
{
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
    ULONG64 hKey;
    PKIWI_HARD_KEY pHardKey;
    PVOID BcryptKey, BufferHardKey = NULL;
    ULONG64 Ptr;

    ULONG BcryptSize;
    ULONG HardKeyOffset;
    ULONG KeyOffset;
    ULONG HandleKeyTagOffset;
    ULONG BcryptTagOffset;
    ULONG HardKeyDataOffset;

#if VERBOSE_MODE
    g_Ext->Dml("g_Ext->m_Minor = %d g_Ext->m_Machine = %x\n", g_Ext->m_Minor, g_Ext->m_Machine);
#endif

    if (g_Ext->m_Machine == IMAGE_FILE_MACHINE_I386)
    {
        if (g_Ext->m_Minor < 8000)
        {
            BcryptSize = sizeof(KIWI_BCRYPT_KEY_X86);
            HardKeyOffset = FIELD_OFFSET(KIWI_BCRYPT_KEY_X86, hardkey);
        }
        else if (g_Ext->m_Minor < 9400)
        {
            BcryptSize = sizeof(KIWI_BCRYPT_KEY8_X86);
            HardKeyOffset = FIELD_OFFSET(KIWI_BCRYPT_KEY8_X86, hardkey);
        }
        else
        {
            BcryptSize = sizeof(KIWI_BCRYPT_KEY81_X86);
            HardKeyOffset = FIELD_OFFSET(KIWI_BCRYPT_KEY81_X86, hardkey);
        }

        KeyOffset = FIELD_OFFSET(KIWI_BCRYPT_HANDLE_KEY_X86, key);
        HandleKeyTagOffset = FIELD_OFFSET(KIWI_BCRYPT_HANDLE_KEY_X86, tag);
        BcryptTagOffset = FIELD_OFFSET(KIWI_BCRYPT_KEY_X86, tag);
    }
    else
    {
        if (g_Ext->m_Minor < 8000)
        {
            BcryptSize = sizeof(KIWI_BCRYPT_KEY_X64);
            HardKeyOffset = FIELD_OFFSET(KIWI_BCRYPT_KEY_X64, hardkey);
        }
        else if (g_Ext->m_Minor < 9400)
        {
            BcryptSize = sizeof(KIWI_BCRYPT_KEY8_X64);
            HardKeyOffset = FIELD_OFFSET(KIWI_BCRYPT_KEY8_X64, hardkey);
        }
        else
        {
            BcryptSize = sizeof(KIWI_BCRYPT_KEY81_X64);
            HardKeyOffset = FIELD_OFFSET(KIWI_BCRYPT_KEY81_X64, hardkey);
        }

        KeyOffset = FIELD_OFFSET(KIWI_BCRYPT_HANDLE_KEY_X64, key);
        HandleKeyTagOffset = FIELD_OFFSET(KIWI_BCRYPT_HANDLE_KEY_X64, tag);
        BcryptTagOffset = FIELD_OFFSET(KIWI_BCRYPT_KEY_X64, tag);
    }

    HardKeyDataOffset = FIELD_OFFSET(KIWI_HARD_KEY, data);

    BcryptKey = malloc(BcryptSize);
    if (!BcryptKey) goto CleanUp;

    if (ReadPointersVirtual(1, phKey, &Ptr) != S_OK) goto CleanUp;

    ULONG Tag;
    if (ReadPointersVirtual(1, Ptr + KeyOffset, &hKey) != S_OK) goto CleanUp;
    if (g_Ext->m_Data->ReadVirtual(Ptr + HandleKeyTagOffset, &Tag, sizeof(ULONG), NULL) != S_OK) goto CleanUp;
    if (Tag != 'UUUR') goto CleanUp;

    if (g_Ext->m_Data->ReadVirtual(hKey + BcryptTagOffset, &Tag, sizeof(ULONG), NULL) != S_OK) goto CleanUp;
    if (Tag != 'MSSK') goto CleanUp;// same as 8

    if (g_Ext->m_Data->ReadVirtual(hKey, BcryptKey, BcryptSize, NULL) != S_OK) goto CleanUp;

    pHardKey = (PKIWI_HARD_KEY)((PBYTE)BcryptKey + HardKeyOffset);
    BufferHardKey = malloc(pHardKey->cbSecret);
    if (!BufferHardKey) goto CleanUp;

    if (g_Ext->m_Data->ReadVirtual(hKey + HardKeyOffset + FIELD_OFFSET(KIWI_HARD_KEY, data), BufferHardKey, pHardKey->cbSecret, NULL) != S_OK) goto CleanUp;
    NtStatus = K_BCryptGenerateSymmetricKey(pGenKey->hProvider, &pGenKey->hKey, pGenKey->pKey, pGenKey->cbKey, (PUCHAR)BufferHardKey, pHardKey->cbSecret, 0);

CleanUp:
    if (BcryptKey) free(BcryptKey);
    if (BufferHardKey) free(BufferHardKey);

    return NtStatus;
}

NTSTATUS
kuhl_m_sekurlsa_nt6_acquireKeys(
    ULONG64 pInitializationVector,
    ULONG64 phAesKey,
    ULONG64 ph3DesKey
)
{
    NTSTATUS NtStatus = STATUS_NOT_FOUND;

    if (g_Ext->m_Data->ReadVirtual(pInitializationVector, &InitializationVector, sizeof(InitializationVector), NULL) != S_OK) goto CleanUp;

    NtStatus = kuhl_m_sekurlsa_nt6_acquireKey(ph3DesKey, &k3Des);
#if VERBOSE_MODE
    g_Ext->Dml("-> kuhl_m_sekurlsa_nt6_acquireKey(Des) = %X\n", NtStatus);
#endif
    if (NT_SUCCESS(NtStatus))
    {
        NtStatus = kuhl_m_sekurlsa_nt6_acquireKey(phAesKey, &kAes);
#if VERBOSE_MODE
        g_Ext->Dml("-> kuhl_m_sekurlsa_nt6_acquireKey(Aes) = %X\n", NtStatus);
#endif
    }

CleanUp:
    return NtStatus;
}

NTSTATUS kuhl_m_sekurlsa_nt6_LsaInitializeProtectedMemory()
{
    NTSTATUS NtStatus;
    ULONG dwSizeNeeded;

    NtStatus = K_BCryptOpenAlgorithmProvider(&k3Des.hProvider, BCRYPT_3DES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(NtStatus)) goto CleanUp;

    NtStatus = K_BCryptSetProperty(k3Des.hProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(NtStatus)) goto CleanUp;

    NtStatus = K_BCryptGetProperty(k3Des.hProvider, BCRYPT_OBJECT_LENGTH, (PBYTE)&k3Des.cbKey, sizeof(k3Des.cbKey), &dwSizeNeeded, 0);
    if (!NT_SUCCESS(NtStatus)) goto CleanUp;
    k3Des.pKey = (PBYTE)malloc(k3Des.cbKey);

    NtStatus = K_BCryptOpenAlgorithmProvider(&kAes.hProvider, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(NtStatus)) goto CleanUp;

    NtStatus = K_BCryptSetProperty(kAes.hProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0);
    if (!NT_SUCCESS(NtStatus)) goto CleanUp;

    NtStatus = K_BCryptGetProperty(kAes.hProvider, BCRYPT_OBJECT_LENGTH, (PBYTE)&kAes.cbKey, sizeof(kAes.cbKey), &dwSizeNeeded, 0);
    if (!NT_SUCCESS(NtStatus)) goto CleanUp; 
    kAes.pKey = (PBYTE)malloc(kAes.cbKey);

CleanUp:
    // g_Ext->Dml("kuhl_m_sekurlsa_nt6_LsaInitializeProtectedMemory(): NtStatus = 0x%X\n", NtStatus);

    return NtStatus;
}

NTSTATUS
kuhl_m_sekurlsa_nt6_init()
{
    if (NT_SUCCESS(kuhl_m_sekurlsa_nt6_KeyInit)) goto CleanUp;

    kuhl_m_sekurlsa_nt6_hBCrypt = LoadLibraryW(L"bcrypt");
    if (!kuhl_m_sekurlsa_nt6_hBCrypt) goto CleanUp;

    K_BCryptOpenAlgorithmProvider = (PBCRYPT_OPEN_ALGORITHM_PROVIDER)GetProcAddress(kuhl_m_sekurlsa_nt6_hBCrypt, "BCryptOpenAlgorithmProvider");
    K_BCryptSetProperty = (PBCRYPT_SET_PROPERTY)GetProcAddress(kuhl_m_sekurlsa_nt6_hBCrypt, "BCryptSetProperty");
    K_BCryptGetProperty = (PBCRYPT_GET_PROPERTY)GetProcAddress(kuhl_m_sekurlsa_nt6_hBCrypt, "BCryptGetProperty");
    K_BCryptGenerateSymmetricKey = (PBCRYPT_GENERATE_SYMMETRIC_KEY)GetProcAddress(kuhl_m_sekurlsa_nt6_hBCrypt, "BCryptGenerateSymmetricKey");
    K_BCryptEncrypt = (PBCRYPT_ENCRYPT)GetProcAddress(kuhl_m_sekurlsa_nt6_hBCrypt, "BCryptEncrypt");
    K_BCryptDecrypt = (PBCRYPT_ENCRYPT)GetProcAddress(kuhl_m_sekurlsa_nt6_hBCrypt, "BCryptDecrypt");
    K_BCryptDestroyKey = (PBCRYPT_DESTROY_KEY)GetProcAddress(kuhl_m_sekurlsa_nt6_hBCrypt, "BCryptDestroyKey");
    K_BCryptCloseAlgorithmProvider = (PBCRYPT_CLOSE_ALGORITHM_PROVIDER)GetProcAddress(kuhl_m_sekurlsa_nt6_hBCrypt, "BCryptCloseAlgorithmProvider");

    if (!kuhl_m_sekurlsa_nt6_hBCrypt || !K_BCryptOpenAlgorithmProvider || !K_BCryptSetProperty ||
        !K_BCryptGetProperty || !K_BCryptGenerateSymmetricKey || !K_BCryptEncrypt ||
        !K_BCryptDecrypt || !K_BCryptDestroyKey || !K_BCryptCloseAlgorithmProvider)
    {
        g_Ext->Dml("One null pointer.\n");
        goto CleanUp;
    }

    kuhl_m_sekurlsa_nt6_KeyInit = kuhl_m_sekurlsa_nt6_LsaInitializeProtectedMemory();

CleanUp:
    // g_Ext->Dml("kuhl_m_sekurlsa_nt6_init(): NtStatus = 0x%X\n", kuhl_m_sekurlsa_nt6_KeyInit);
    return kuhl_m_sekurlsa_nt6_KeyInit;
}

const KUHL_M_SEKURLSA_ENUM_HELPER lsassEnumHelpers_X86[] = {
    { sizeof(KIWI_MSV1_0_LIST_60_X86), FIELD_OFFSET(KIWI_MSV1_0_LIST_60_X86, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_60_X86, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_60_X86, Session), FIELD_OFFSET(KIWI_MSV1_0_LIST_60_X86, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_60_X86, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_60_X86, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_60_X86, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_60_X86, CredentialManager) },
    { sizeof(KIWI_MSV1_0_LIST_61_X86), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_X86, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_X86, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_X86, Session), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_X86, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_X86, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_X86, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_X86, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_X86, CredentialManager) },
    { sizeof(KIWI_MSV1_0_LIST_62_X86), FIELD_OFFSET(KIWI_MSV1_0_LIST_62_X86, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_62_X86, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_62_X86, Session), FIELD_OFFSET(KIWI_MSV1_0_LIST_62_X86, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_62_X86, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_62_X86, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_62_X86, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_62_X86, CredentialManager) },
    { sizeof(KIWI_MSV1_0_LIST_63_X86), FIELD_OFFSET(KIWI_MSV1_0_LIST_63_X86, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_63_X86, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_63_X86, Session), FIELD_OFFSET(KIWI_MSV1_0_LIST_63_X86, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_63_X86, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_63_X86, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_63_X86, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_63_X86, CredentialManager) },
};

const KUHL_M_SEKURLSA_ENUM_HELPER lsassEnumHelpers_X64[] = {
    { sizeof(KIWI_MSV1_0_LIST_60_X64), FIELD_OFFSET(KIWI_MSV1_0_LIST_60_X64, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_60_X64, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_60_X64, Session), FIELD_OFFSET(KIWI_MSV1_0_LIST_60_X64, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_60_X64, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_60_X64, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_60_X64, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_60_X64, CredentialManager) },
    { sizeof(KIWI_MSV1_0_LIST_61_X64), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_X64, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_X64, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_X64, Session), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_X64, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_X64, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_X64, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_X64, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_X64, CredentialManager) },
    { sizeof(KIWI_MSV1_0_LIST_62_X64), FIELD_OFFSET(KIWI_MSV1_0_LIST_62_X64, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_62_X64, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_62_X64, Session), FIELD_OFFSET(KIWI_MSV1_0_LIST_62_X64, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_62_X64, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_62_X64, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_62_X64, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_62_X64, CredentialManager) },
    { sizeof(KIWI_MSV1_0_LIST_63_X64), FIELD_OFFSET(KIWI_MSV1_0_LIST_63_X64, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_63_X64, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_63_X64, Session), FIELD_OFFSET(KIWI_MSV1_0_LIST_63_X64, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_63_X64, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_63_X64, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_63_X64, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_63_X64, CredentialManager) },
};

const char * KUHL_M_SEKURLSA_LOGON_TYPE[] = {
    "UndefinedLogonType", "Unknown !", "Interactive", "Network",
    "Batch", "Service", "Proxy", "Unlock", "NetworkCleartext",
    "NewCredentials", "RemoteInteractive", "CachedInteractive",
    "CachedRemoteInteractive", "CachedUnlock",
};

void
Mimikatz()
{
    ULONG64 pInitializationVector, phAesKey, ph3DesKey, pLogonSessionList, pLogonSessionListCount;
    PULONG64 LogonSessionList = NULL;
    ULONG LogonSessionListCount, i, j;
    PBYTE Buffer = NULL;

    const KUHL_M_SEKURLSA_ENUM_HELPER *Helper;

    KIWI_BASIC_SECURITY_LOGON_SESSION_DATA SessionData;

    MsProcessObject ProcessObject = FindProcessByName("lsass.exe");

    ProcessObject.SwitchContext();

    g_Ext->ExecuteSilent(".process /p /r 0x%I64X", ProcessObject.m_CcProcessObject.ProcessObjectPtr);

    // if (g_Ext->m_Control->GetActualProcessorType(&g_ProcessorType) != S_OK) goto CleanUp;
    // if (g_Ext->m_Control->GetSystemVersion(&g_Ext->m_Machine, &g_Major, &g_Ext->m_Minor, NULL, NULL, NULL, &g_ServicePackNumber, NULL, NULL, NULL) != S_OK) goto CleanUp;

    if (g_Ext->m_Machine == IMAGE_FILE_MACHINE_I386)
    {
        if (g_Ext->m_Minor < KULL_M_WIN_MIN_BUILD_7) Helper = &lsassEnumHelpers_X86[0];
        else if (g_Ext->m_Minor < KULL_M_WIN_MIN_BUILD_8) Helper = &lsassEnumHelpers_X86[1];
        else if (g_Ext->m_Minor < KULL_M_WIN_MIN_BUILD_BLUE) Helper = &lsassEnumHelpers_X86[2];
        else Helper = &lsassEnumHelpers_X86[3];
    }
    else
    {
        if (g_Ext->m_Minor < KULL_M_WIN_MIN_BUILD_7) Helper = &lsassEnumHelpers_X64[0];
        else if (g_Ext->m_Minor < KULL_M_WIN_MIN_BUILD_8) Helper = &lsassEnumHelpers_X64[1];
        else if (g_Ext->m_Minor < KULL_M_WIN_MIN_BUILD_BLUE) Helper = &lsassEnumHelpers_X64[2];
        else Helper = &lsassEnumHelpers_X64[3];
    }

#if VERBOSE_MODE
    g_Ext->Dml("Get variables..\n");
#endif

    if (g_Ext->m_Symbols->GetOffsetByName("lsasrv!InitializationVector", &pInitializationVector) != S_OK) goto CleanUp;
    if (g_Ext->m_Symbols->GetOffsetByName("lsasrv!hAesKey", &phAesKey) != S_OK) goto CleanUp;
    if (g_Ext->m_Symbols->GetOffsetByName("lsasrv!h3DesKey", &ph3DesKey) != S_OK) goto CleanUp;

    if (g_Ext->m_Symbols->GetOffsetByName("lsasrv!LogonSessionList", &pLogonSessionList) != S_OK) goto CleanUp;
    if (g_Ext->m_Symbols->GetOffsetByName("lsasrv!LogonSessionListCount", &pLogonSessionListCount) != S_OK) goto CleanUp;

#if VERBOSE_MODE
    g_Ext->Dml("Got variables..\n");
#endif

    if (!pInitializationVector || !phAesKey || !ph3DesKey) goto CleanUp;
    if (!pLogonSessionListCount || !pLogonSessionList) goto CleanUp;


    for (j = 0; j < sizeof(packages) / sizeof(KUHL_M_SEKURLSA_PACKAGE); j++)
    {
        if (packages[j].symbolName) g_Ext->m_Symbols->GetOffsetByName(packages[j].symbolName, &packages[j].symbolPtr);
    }

#if VERBOSE_MODE
    g_Ext->Dml("One\n");
#endif

    if (!NT_SUCCESS(kuhl_m_sekurlsa_nt6_init())) goto CleanUp;

#if VERBOSE_MODE
    g_Ext->Dml("Two\n");
#endif

    if (!NT_SUCCESS(kuhl_m_sekurlsa_nt6_acquireKeys(pInitializationVector, phAesKey, ph3DesKey))) goto CleanUp;

#if VERBOSE_MODE
    g_Ext->Dml("Three\n");
#endif

    if (g_Ext->m_Data->ReadVirtual(pLogonSessionListCount, &LogonSessionListCount, sizeof(ULONG), NULL) != S_OK) goto CleanUp;

#if VERBOSE_MODE
    g_Ext->Dml("Four\n");
#endif

    ULONG NumberOfPointers = 2 /* Flink + Blink */ * LogonSessionListCount;

    ULONG ListEntrySize = GetTypeSize("nt!_LIST_ENTRY");
    LogonSessionList = (PULONG64)malloc(sizeof(ULONG64)* NumberOfPointers);
    if (!LogonSessionList) goto CleanUp;

    if (ReadPointersVirtual(NumberOfPointers, pLogonSessionList, (PULONG64)LogonSessionList) != S_OK) goto CleanUp;

    Buffer = (PBYTE)malloc(Helper->tailleStruct);
    if (!Buffer) goto CleanUp;

    g_Ext->Dml("LogonSessionListCount: %d\n", LogonSessionListCount);
    for (i = 0; i < LogonSessionListCount; i++)
    {
        ULONG64 Flink = LogonSessionList[i * 2]; // Flink;

        // g_Ext->Dml("Flink = %I64X\n", Flink);
        ExtRemoteTypedList SessionList(pLogonSessionList + ListEntrySize * i, "nt!_LIST_ENTRY", "Flink");

        for (SessionList.StartHead();
            SessionList.HasNode();
            SessionList.Next())
        {
            Flink = SessionList.GetNodeOffset();

            g_Ext->Dml("Flink2 = %I64X\n", Flink);

            if (g_Ext->m_Data->ReadVirtual(Flink, Buffer, Helper->tailleStruct, NULL) != S_OK) break;

            // g_Ext->Dml("Flink + Helper->offsetToLuid = [0x%I64X] = ", Flink + Helper->offsetToLuid);
            if (ReadPointersVirtual(1, Flink + Helper->offsetToLuid, (PULONG64)&SessionData.LogonId) != S_OK) goto CleanUp;
            //g_Ext->Dml("0x%I64X \n", LogonIdAddr);

            //if (g_Ext->m_Data->ReadVirtual(LogonIdAddr, &SessionData.LogonId, sizeof(SessionData.LogonId), NULL) != S_OK) break;

            // g_Ext->Dml("Luid = 0x%08X0x%08X \n", SessionData.LogonId.HighPart, SessionData.LogonId.LowPart);

            SessionData.LogonType = *((PULONG)(Buffer + Helper->offsetToLogonType));
            SessionData.Session = *((PULONG)(Buffer + Helper->offsetToSession));
            SessionData.UserName = Flink + Helper->offsetToUsername;
            SessionData.LogonDomain = Flink + Helper->offsetToDomain;

            if (ReadPointersVirtual(1, Flink + Helper->offsetToCredentials, (PULONG64)&SessionData.pCredentials) != S_OK) goto CleanUp;
            if (ReadPointersVirtual(1, Flink + Helper->offsetToPSid, (PULONG64)&SessionData.pSid) != S_OK) goto CleanUp;
            if (ReadPointersVirtual(1, Flink + Helper->offsetToCredentialManager, (PULONG64)&SessionData.pCredentialManager) != S_OK) goto CleanUp;

            if ((SessionData.LogonType != Network) /*&& (sessionData.LogonType != UndefinedLogonType)*/)
            {
                WCHAR UserName[128];
                WCHAR LogonDomain[128];

                ExtRemoteTyped UserNameTyped("(nt!_UNICODE_STRING *)@$extin", (ULONG64)SessionData.UserName);
                ExtRemoteTypedEx::GetUnicodeString(UserNameTyped, UserName, sizeof(UserName));
                ExtRemoteTyped LogonDomainTyped("(nt!_UNICODE_STRING *)@$extin", (ULONG64)SessionData.LogonDomain);
                ExtRemoteTypedEx::GetUnicodeString(LogonDomainTyped, LogonDomain, sizeof(LogonDomain));

                // kuhl_m_sekurlsa_utils_getSid(&sessionData.pSid);
                g_Ext->Dml("\n"
                            "    Authentication Id  : 0x%08X%08X\n"
                            "    Session            : %s from %u\n"
                            "    <col fg=\"changed\">User Name</col>          : <col fg=\"emphfg\">%S</col>\n"
                            "    <col fg=\"changed\">Domain</col>             : <col fg=\"emphfg\">%S</col>\n"
                            "    SID                : <link cmd=\"!sid 0x%I64X\">0x%I64X</link>\n",
                    SessionData.LogonId.HighPart, SessionData.LogonId.LowPart,
                    KUHL_M_SEKURLSA_LOGON_TYPE[SessionData.LogonType], SessionData.Session,
                    UserName, LogonDomain, SessionData.pSid, SessionData.pSid);

                for (j = 0; j < sizeof(packages) / sizeof(KUHL_M_SEKURLSA_PACKAGE); j++)
                {
                    if (packages[j].symbolPtr || !packages[j].symbolName)
                    {
                        // g_Ext->Dml("    %s : \n", packages[j].name);
                        packages[j].callback(packages[j].symbolPtr, &SessionData);
                        // g_Ext->Dml("\n");
                    }
                }
            }
        }
    }

CleanUp:
    ProcessObject.RestoreContext();

    if (LogonSessionList) free(LogonSessionList);
    if (Buffer) free(Buffer);

    return;
}