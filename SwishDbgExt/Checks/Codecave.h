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

    - Codecave.h

Abstract:

    - https ://breakingmalware.com/injection-techniques/atombombing-brand-new-code-injection-for-windows/

Environment:

    - User mode

Revision History:

    - Matthieu Suiche (m)

--*/

#ifndef __CODECAVE_H__
#define __CODECAVE_H__

ULONG
HasUsedCodeCave(
    ULONG64 ImageBase,
    vector<MsPEImageFile::CACHED_SECTION_INFO> *Sections,
    MsPEImageFile::PCACHED_SECTION_INFO SectionHeader,
    PULONG Score
);

#endif