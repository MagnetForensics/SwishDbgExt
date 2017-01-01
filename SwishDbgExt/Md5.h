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

    - Md5.h

Abstract:

    - ExtRemoteData Pointer(GetExpression("'htsxxxxx!gRingBuffer"), m_PtrSize); // <<< works just fine

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/


#ifndef __MD5_H__
#define __MD5_H__

//
// Data structure for MD5 (Message Digest) computation 
//
typedef struct _MD5_CONTEXT {
    ULONG i[2]; /* number of _bits_ handled mod 2^64 */
    ULONG Buffer[4]; /* scratch Bufferfer */
    UCHAR In[64]; /* Input Bufferfer */
    UCHAR Digest[16]; /* actual Digest after MD5FInal call */
} MD5_CONTEXT, *PMD5_CONTEXT;

void
MD5Init(
    MD5_CONTEXT *Md5Context
);

void
MD5Update(
    MD5_CONTEXT *Md5Context,
    unsigned char *InBuf,
    unsigned long InLen
);

void
MD5Final(
    MD5_CONTEXT *Md5Context
);

#endif