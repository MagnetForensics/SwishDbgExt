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

    - Security.h

Abstract:

    - Thanks to Frank Boldewin for sharing his code.

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#ifndef __SECURITY_H__
#define __SECURITY_H__

ULONG
GetMalScore(
    BOOLEAN Verbose,
    ULONG64 VirtualAddress,
    LPBYTE Buffer,
    ULONG BufferLen
);

ULONG
GetMalScoreEx(
    BOOLEAN Verbose,
    MsProcessObject *ProcObj,
    ULONG64 BaseAddress,
    ULONG Length
);
#endif