/*++
    Incident Response & Digital Forensics Debugging Extension

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

    - Output.h

Abstract:

    - ExtRemoteData Pointer(GetExpression("'htsxxxxx!gRingBuffer"), m_PtrSize); // <<< works just fine

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#ifndef __OUTPUT_H__
#define __OUTPUT_H__

extern LPSTR IrpMajor[];

VOID
OutThread(
PTHREAD_OBJECT Thread
);

VOID
OutHandles(
PHANDLE_OBJECT Handle
);

VOID
OutDriver(
    MsDriverObject *Driver,
    ULONG ExpandFlag
);

LPSTR
GetLastWriteTime(
    PFILETIME ftWrite,
    LPSTR Buffer,
    ULONG dwSize
);

#endif