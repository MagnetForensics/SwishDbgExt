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

#include "stdafx.h"
#include "../SwishDbgExt.h"

#define VERBOSE FALSE

ULONG
HasUsedCodeCave(
    ULONG64 ImageBase,
    vector<MsPEImageFile::CACHED_SECTION_INFO> *Sections,
    MsPEImageFile::PCACHED_SECTION_INFO SectionHeader,
    PULONG Score
)
{
    ULONG Result = FALSE;
    PUCHAR Buffer = NULL;
    ULONG CorruptionScore = 0;

    ULONG CodeCaveVirtualOffset = SectionHeader->VaBase + min(SectionHeader->VaSize, SectionHeader->RawSize);

    ULONG DeadSpace = TRUE;
    for each (MsPEImageFile::CACHED_SECTION_INFO current in *Sections) {
        if (current.VaBase == CodeCaveVirtualOffset) {

            if (g_Verbose) g_Ext->Dml("[%s!%S!%d] '%s' ends right before '%s' .\n", __FILE__, __FUNCTIONW__, __LINE__, SectionHeader->Name, current.Name);
            DeadSpace = FALSE;
            goto CleanUp;
        }
    }

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
    for (ULONG i = 0; i < min(BytesLeft, 0x10); i += 1) {
        if ((Buffer[i] != '\xff') && (Buffer[i] != '\0')) {
            CorruptionScore += 1;
        }
    }

    if (CorruptionScore) {
        if (g_Verbose) {
            g_Ext->Dml("            0x%llx + 0x%x + 0x%x = 0x%llx\n", ImageBase, SectionHeader->VaBase, SectionHeader->RawSize, ImageBase + SectionHeader->VaBase + SectionHeader->RawSize);
            g_Ext->Dml("            Data[0] = 0x%02X, Data[1] = 0x%02X, Data[2] = 0x%02X, Data[3] = 0x%02X, \n", Buffer[0], Buffer[1], Buffer[2], Buffer[3]);
            g_Ext->Execute("u 0x%I64X", TargetVa);
        }

        Result = CodeCaveVirtualOffset;
        goto CleanUp;
    }

CleanUp:
    *Score = CorruptionScore;
    if (Buffer) free(Buffer);

    return Result;
}