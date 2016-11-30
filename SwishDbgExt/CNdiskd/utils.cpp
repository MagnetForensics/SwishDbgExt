/*++
    A NDIS hook scan extension to existing MoonSols Incident Response & Digital Forensics Debugging Extension

	Copyright (C) 2014 wLcY (@x9090)

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
--*/
#include <intsafe.h>
#include "..\SwishDbgExt.h" // DbgPrint macro
#include "CNdiskd.h"

#define SIGN_EXTEND(_x_) (ULONG64)(LONG)(_x_)

//////////////////////////////////////////////////////////////////////////
// Documented structure definitions
//////////////////////////////////////////////////////////////////////////
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR   Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

namespace utils {

	BOOL IsVistaOrAbove()
	{
		BOOL bIsWindowsVistaOrLater = false;
		ULONG PlatformId, Win32Major, Win32Minor;
		HRESULT hres;
		ULONG strSize = 0;

		hres = g_Ext->m_Control4->GetSystemVersionValues(&PlatformId, &Win32Major, &Win32Minor, NULL, NULL);

		if ( FAILED( hres )  )
			g_Ext->ThrowRemote(hres, "IDebugControl4::GetSystemVersionValues" );

		bIsWindowsVistaOrLater = Win32Major == 6;

		if (bIsWindowsVistaOrLater)
			return true;
		else
			return false;
	}

	ULONG64 findModuleBase(PCSTR moduleName)
	{
		HRESULT     hres;
		ULONG64     base;

		hres = g_Ext->m_Symbols->GetModuleByModuleName(moduleName, 0, NULL, &base);

		if ( FAILED( hres ) )
			g_Ext->ThrowRemote(hres, "IDebugSymbol::GetModuleByModuleName");

		return base;
	}

	ULONG64 findModuleBase(PWSTR moduleName)
	{
		HRESULT     hres;
		ULONG64     base;

		hres = g_Ext->m_Symbols3->GetModuleByModuleNameWide(moduleName, 0, NULL, &base);

		if ( FAILED( hres ) )
			g_Ext->ThrowRemote(hres, "IDebugSymbol3::GetModuleByModuleName");

		return base;
	}

	ULONG64 findModuleBase(ULONG64 offset)
	{
		HRESULT     hres;
		ULONG64     base;
		ULONG       moduleIndex;

		// 32-bit
		if (g_Ext->IsMachine32(g_Ext->m_ActualMachine))
			hres = g_Ext->m_Symbols->GetModuleByOffset(SIGN_EXTEND(offset), 0, &moduleIndex, &base);
		// 64-bit
		else
			hres = g_Ext->m_Symbols->GetModuleByOffset(offset, 0, &moduleIndex, &base);

		if ( FAILED( hres ) )
			g_Ext->ThrowRemote(hres, "IDebugSymbol::GetModuleByOffset. Try reloading symbols (.reload /f)");

		return base;
	}

	ULONG64 getNdisFieldData(ULONG64 Base, ExtRemoteTyped TypedObj, PSTR FieldName)
	{
		CHAR NewFieldName[100] = {0};
		ULONG64 Address;

		// Is object type NDIS_PROTOCOL_BLOCK?
		if (strstr(TypedObj.GetTypeName(), "_NDIS_PROTOCOL_BLOCK") != NULL)
		{
			// Ndis6x does not have ProtocolCharaterisitics
			if (utils::IsVistaOrAbove())
			{
				strcpy_s(NewFieldName, FieldName);
			}
			// Ndis5x has a union structure ProtocolCharaterisitics
			else 
			{
				if(strcmp(FieldName, "MajorNdisVersion") == 0 || 
					strcmp(FieldName, "MinorNdisVersion") == 0 ||
					strcmp(FieldName, "Name") == 0 ||
					strcmp(FieldName, "Filler") == 0 ||
					strcmp(FieldName, "Reserved") == 0 ||
					strcmp(FieldName, "Flags") == 0 ||
					strstr(FieldName, "Handler") != NULL)
				{
					strcpy_s(NewFieldName, "ProtocolCharacteristics.");
					strcat_s(NewFieldName, FieldName);
				}
				else
				{
					strcpy_s(NewFieldName, FieldName);
				}
			}
		}
		else
		{
			strcpy_s(NewFieldName, FieldName);
		}

		if (Base > 0)
		{
			Address = Base + TypedObj.GetFieldOffset(NewFieldName);
			return Address;
		}
		else
		{
			switch(TypedObj.Field(NewFieldName).GetTypeSize())
			{
			case 8:
				return TypedObj.Field(NewFieldName).GetLong64();
			case 4:
				return TypedObj.Field(NewFieldName).GetLong();
			case 2:
				return TypedObj.Field(NewFieldName).GetUshort();
			case 1:
				return TypedObj.Field(NewFieldName).GetUchar();
			default:
				return TypedObj.Field(NewFieldName).GetBoolean();
			}
		}
	}

	ULONG64 getPointerFromAddress(ULONG64 Address, PULONG cbBytesRead)
	{
		ULONG Status;
		ULONG64 Result;

		Result = 0;
		if (g_Ext->IsMachine32(g_Ext->m_ActualMachine))
		{
			// SIGN_EXTEND: To mitigate ReadVirtual: xxxxxxxx not properly sign extended warning
			Status = ReadMemory(SIGN_EXTEND(Address), &Result, 4, cbBytesRead);
		}
		else
		{
			Status = ReadMemory(Address, &Result, 8, cbBytesRead);
		}

		if (Status == FALSE)
		{
			g_Ext->m_Control->Output(DEBUG_OUTPUT_ERROR, "Failed to read pointer from 0x%I64x.\n", Address);
		}

		return Result;
	}

	ULONG getUlongFromAddress(ULONG64 Address, PULONG cbBytesRead)
	{
		ULONG Status;
		ULONG Result;

		Result = 0;
		*cbBytesRead = 0;
		Status = ReadMemory(Address, &Result, sizeof(ULONG), cbBytesRead);

		if(Status == FALSE)
		{
			g_Ext->m_Control->Output(DEBUG_OUTPUT_ERROR, "Failed to read value from 0x%I64x.", Address);
		}
		else if(*cbBytesRead != sizeof(ULONG))
		{
			g_Ext->m_Control->Output(DEBUG_OUTPUT_ERROR, "Something wrong when reading value from 0x%I64x.", Address);
		}

		return Result;
	}

	namespace {

		ULONG getModuleSizeImpl( ULONG64 baseOffset )
		{
			HRESULT  hres;
			DEBUG_MODULE_PARAMETERS     moduleParam = { 0 };

			hres = g_Ext->m_Symbols->GetModuleParameters(1, &baseOffset, 0, &moduleParam);
			if ( FAILED( hres ) )
				g_Ext->ThrowRemote(hres, "IDebugSymbol::GetModuleParameters");

			return moduleParam.Size;
		}
	}

	ULONG getModuleSize( ULONG64 baseOffset )
	{
		// 32-bit
		if (g_Ext->IsMachine32(g_Ext->m_ActualMachine))
			return getModuleSizeImpl( SIGN_EXTEND(baseOffset) );
		// 64-bit
		else
			return getModuleSizeImpl( baseOffset );
	}

	PSTR getNameByOffset(ULONG64 addr, PSTR symbolName)
	{
		HRESULT	hres;
		ULONG64	displace = 0;

		RtlZeroMemory(symbolName, sizeof(symbolName));

		// 32-bit
		if (g_Ext->IsMachine32(g_Ext->m_ActualMachine))
			hres = g_Ext->m_Symbols->GetNameByOffset(SIGN_EXTEND(addr), symbolName, sizeof(symbolName), NULL, &displace);
		// 64-bit
		else
			hres = g_Ext->m_Symbols->GetNameByOffset(addr, symbolName, sizeof(symbolName), NULL, &displace);

		if ( FAILED( hres ) )
		{
			//g_Ext->ThrowRemote(hres, "IDebugSymbol::GetNameByOffset failed at 0x%I64x.", addr);
			return NULL;
		}

		return symbolName;
	}

	PSTR getModuleNameByOffset(ULONG64 addr, PSTR moduleName)
	{
		HRESULT	hres;
		ULONG	moduleIndex;
		ULONG64	moduleBase;

		RtlZeroMemory(moduleName, sizeof(moduleName));

		// 32-bit
		if (g_Ext->IsMachine32(g_Ext->m_ActualMachine))
			hres = g_Ext->m_Symbols->GetModuleByOffset(SIGN_EXTEND(addr), 0, &moduleIndex, &moduleBase);
		// 64-bit
		else
			hres = g_Ext->m_Symbols->GetModuleByOffset(addr, 0, &moduleIndex, &moduleBase);

		if ( FAILED( hres ) )
		{
			//g_Ext->ThrowRemote(hres, "IDebugSymbol::GetModuleByOffset failed at 0x%I64x.", addr);
			return NULL;
		}

		hres = g_Ext->m_Symbols2->GetModuleNameString(DEBUG_MODNAME_LOADED_IMAGE, moduleIndex, moduleBase, moduleName, sizeof(moduleName), NULL);

		if ( FAILED( hres ) )
		{
			//g_Ext->ThrowRemote(hres, "IDebugSymbol::GetNameByOffset  failed" );
			return NULL;
		}

		return moduleName;
	}

	PWSTR getUnicodeString(
		IN ExtRemoteTyped TypedObject,
		OUT PWSTR Buffer,
		IN ULONG MaxChars)
	{
		UNICODE_STRING SavedUnicodeString = {0};

		RtlZeroMemory(Buffer, MaxChars);

		SavedUnicodeString.Length = TypedObject.Field("Length").GetUshort();
		SavedUnicodeString.MaximumLength = TypedObject.Field("MaximumLength").GetUshort();
		SavedUnicodeString.Buffer = (PWCH)TypedObject.Field("Buffer").GetPtr();

		if (SavedUnicodeString.Buffer && SavedUnicodeString.Length)
		{
			ExtRemoteData usData((ULONG64)SavedUnicodeString.Buffer, SavedUnicodeString.Length);

			if (SavedUnicodeString.Length > MaxChars)
			{
				g_Ext->ThrowRemote(HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW),
					"String at %p overflows buffer, need 0x%x chars",
					TypedObject.m_Offset, SavedUnicodeString.Length);
			}

#if VVERBOSE_MODE
			ULONG64 ptrBuffer = (ULONG64)SavedUnicodeString.Buffer;
			DbgPrint("DEBUG: %s:%d:%s Get string from %#I64x with length %d to %#p\n", __FILE__, __LINE__, __FUNCTION__, ptrBuffer, SavedUnicodeString.Length, Buffer);
#endif
			usData.GetString(Buffer, SavedUnicodeString.Length, SavedUnicodeString.MaximumLength, false, NULL);
		}

		// Some string is not NULL terminated
		Buffer[SavedUnicodeString.MaximumLength/sizeof(WCHAR)] = '\0';
		return Buffer;
	}


}