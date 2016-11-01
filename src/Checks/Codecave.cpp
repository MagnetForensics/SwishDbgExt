                                                                                                                  /*++
    Comae Incident Response & Digital Forensics Debugging Extension

    Copyright (C) 2016 Comae Technologies FZE.
    Copyright (C) 2016 Matthieu Suiche (@msuiche)

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

    - Codecave.cpp

Abstract:

    - https ://breakingmalware.com/injection-techniques/atombombing-brand-new-code-injection-for-windows/

Environment:

    - User mode

Revision History:

    - Matthieu Suiche (m)

--*/

#include "../MoonSolsDbgExt.h"

#define VERBOSE FALSE

ULONG
HasUsedCodeCave(
    ULONG64 ImageBase,
    PEFile::PCACHED_SECTION_INFO SectionHeader
)
{
    ULONG Result = FALSE;
    PUCHAR Buffer = NULL;

    ULONG CodeCaveVirtualOffset = SectionHeader->VaBase + SectionHeader->RawSize;

    ULONG BytesLeft = PAGE_SIZE - (CodeCaveVirtualOffset & (PAGE_SIZE - 1));
    if (!BytesLeft) goto CleanUp;

    Buffer = (LPBYTE)malloc(BytesLeft);
    if (Buffer == NULL) goto CleanUp;

    ULONG64 TargetVa = SIGN_EXTEND(ImageBase + CodeCaveVirtualOffset);

    if (ExtRemoteTypedEx::ReadVirtual(TargetVa, Buffer, BytesLeft, NULL) != S_OK) {
        goto CleanUp;
    }

    //
    // Simple check, to know if the code space null or did someone wrote something into it ?
    //
    if (Buffer[0] != '\0') {
        if (TRUE) {
            g_Ext->Dml("            Data[0] = 0x%02X, Data[1] = 0x%02X, Data[2] = 0x%02X, Data[3] = 0x%02X, \n", Buffer[0], Buffer[1], Buffer[2], Buffer[3]);
            g_Ext->Execute("u 0x%I64X", TargetVa);
        }
        Result = CodeCaveVirtualOffset;
        goto CleanUp;
    }

CleanUp:
    if (Buffer) free(Buffer);

    return Result;
}