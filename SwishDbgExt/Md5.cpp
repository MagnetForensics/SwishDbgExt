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

    - Md5.c

Abstract:

    - 

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#include "stdafx.h"
#include "SwishDbgExt.h"


/* F, G and H are basic MD5 functions: selection, majority, parity */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z))) 

/* ROTATE_LEFT rotates x left n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s, ac) \
  {(a) += F ((b), (c), (d)) + (x) + (UINT32)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) \
  {(a) += G ((b), (c), (d)) + (x) + (UINT32)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) \
  {(a) += H ((b), (c), (d)) + (x) + (UINT32)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) \
  {(a) += I ((b), (c), (d)) + (x) + (UINT32)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }

/*
 **********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. **
 **                                                                  **
 ** License to copy and use this software is granted provided that   **
 ** it is identified as the "RSA Data Security, Inc. MD5 Message     **
 ** Digest Algorithm" In all material mentionIng or referencIng this **
 ** software or this function.                                       **
 **                                                                  **
 ** License is also granted to make and use derivative works         **
 ** provided that such works are identified as "derived from the RSA **
 ** Data Security, Inc. MD5 Message Digest Algorithm" In all         **
 ** material mentionIng or referencIng the derived work.             **
 **                                                                  **
 ** RSA Data Security, Inc. makes no representations concernIng      **
 ** either the merchantability of this software or the suitability   **
 ** of this software for any particular purpose.  It is provided "as **
 ** is" without express or implied warranty of any kInd.             **
 **                                                                  **
 ** These notices must be retaIned In any copies of any part of this **
 ** documentation and/or software.                                   **
 **********************************************************************
 */

UCHAR PADDING[64] = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Basic MD5 step. Transform Buffer based on In.
*/
VOID
Transform(
    _Inout_ ULONG *Buffer,
    _Inout_ ULONG *In
)
/*++

Routine Description:

    Description.

Arguments:

    Buffer - 
    In -

Return Value:

    VOID.

--*/
{
    ULONG a = Buffer[0], b = Buffer[1], c = Buffer[2], d = Buffer[3];

    /* Round 1 */
    #define S11 7
    #define S12 12
    #define S13 17
    #define S14 22
    FF ( a, b, c, d, In[ 0], S11, 3614090360); /* 1 */
    FF ( d, a, b, c, In[ 1], S12, 3905402710); /* 2 */
    FF ( c, d, a, b, In[ 2], S13,  606105819); /* 3 */
    FF ( b, c, d, a, In[ 3], S14, 3250441966); /* 4 */
    FF ( a, b, c, d, In[ 4], S11, 4118548399); /* 5 */
    FF ( d, a, b, c, In[ 5], S12, 1200080426); /* 6 */
    FF ( c, d, a, b, In[ 6], S13, 2821735955); /* 7 */
    FF ( b, c, d, a, In[ 7], S14, 4249261313); /* 8 */
    FF ( a, b, c, d, In[ 8], S11, 1770035416); /* 9 */
    FF ( d, a, b, c, In[ 9], S12, 2336552879); /* 10 */
    FF ( c, d, a, b, In[10], S13, 4294925233); /* 11 */
    FF ( b, c, d, a, In[11], S14, 2304563134); /* 12 */
    FF ( a, b, c, d, In[12], S11, 1804603682); /* 13 */
    FF ( d, a, b, c, In[13], S12, 4254626195); /* 14 */
    FF ( c, d, a, b, In[14], S13, 2792965006); /* 15 */
    FF ( b, c, d, a, In[15], S14, 1236535329); /* 16 */

    /* Round 2 */
    #define S21 5
    #define S22 9
    #define S23 14
    #define S24 20
    GG ( a, b, c, d, In[ 1], S21, 4129170786); /* 17 */
    GG ( d, a, b, c, In[ 6], S22, 3225465664); /* 18 */
    GG ( c, d, a, b, In[11], S23,  643717713); /* 19 */
    GG ( b, c, d, a, In[ 0], S24, 3921069994); /* 20 */
    GG ( a, b, c, d, In[ 5], S21, 3593408605); /* 21 */
    GG ( d, a, b, c, In[10], S22,   38016083); /* 22 */
    GG ( c, d, a, b, In[15], S23, 3634488961); /* 23 */
    GG ( b, c, d, a, In[ 4], S24, 3889429448); /* 24 */
    GG ( a, b, c, d, In[ 9], S21,  568446438); /* 25 */
    GG ( d, a, b, c, In[14], S22, 3275163606); /* 26 */
    GG ( c, d, a, b, In[ 3], S23, 4107603335); /* 27 */
    GG ( b, c, d, a, In[ 8], S24, 1163531501); /* 28 */
    GG ( a, b, c, d, In[13], S21, 2850285829); /* 29 */
    GG ( d, a, b, c, In[ 2], S22, 4243563512); /* 30 */
    GG ( c, d, a, b, In[ 7], S23, 1735328473); /* 31 */
    GG ( b, c, d, a, In[12], S24, 2368359562); /* 32 */

    /* Round 3 */
    #define S31 4
    #define S32 11
    #define S33 16
    #define S34 23
    HH ( a, b, c, d, In[ 5], S31, 4294588738); /* 33 */
    HH ( d, a, b, c, In[ 8], S32, 2272392833); /* 34 */
    HH ( c, d, a, b, In[11], S33, 1839030562); /* 35 */
    HH ( b, c, d, a, In[14], S34, 4259657740); /* 36 */
    HH ( a, b, c, d, In[ 1], S31, 2763975236); /* 37 */
    HH ( d, a, b, c, In[ 4], S32, 1272893353); /* 38 */
    HH ( c, d, a, b, In[ 7], S33, 4139469664); /* 39 */
    HH ( b, c, d, a, In[10], S34, 3200236656); /* 40 */
    HH ( a, b, c, d, In[13], S31,  681279174); /* 41 */
    HH ( d, a, b, c, In[ 0], S32, 3936430074); /* 42 */
    HH ( c, d, a, b, In[ 3], S33, 3572445317); /* 43 */
    HH ( b, c, d, a, In[ 6], S34,   76029189); /* 44 */
    HH ( a, b, c, d, In[ 9], S31, 3654602809); /* 45 */
    HH ( d, a, b, c, In[12], S32, 3873151461); /* 46 */
    HH ( c, d, a, b, In[15], S33,  530742520); /* 47 */
    HH ( b, c, d, a, In[ 2], S34, 3299628645); /* 48 */

    /* Round 4 */
    #define S41 6
    #define S42 10
    #define S43 15
    #define S44 21
    II ( a, b, c, d, In[ 0], S41, 4096336452); /* 49 */
    II ( d, a, b, c, In[ 7], S42, 1126891415); /* 50 */
    II ( c, d, a, b, In[14], S43, 2878612391); /* 51 */
    II ( b, c, d, a, In[ 5], S44, 4237533241); /* 52 */
    II ( a, b, c, d, In[12], S41, 1700485571); /* 53 */
    II ( d, a, b, c, In[ 3], S42, 2399980690); /* 54 */
    II ( c, d, a, b, In[10], S43, 4293915773); /* 55 */
    II ( b, c, d, a, In[ 1], S44, 2240044497); /* 56 */
    II ( a, b, c, d, In[ 8], S41, 1873313359); /* 57 */
    II ( d, a, b, c, In[15], S42, 4264355552); /* 58 */
    II ( c, d, a, b, In[ 6], S43, 2734768916); /* 59 */
    II ( b, c, d, a, In[13], S44, 1309151649); /* 60 */
    II ( a, b, c, d, In[ 4], S41, 4149444226); /* 61 */
    II ( d, a, b, c, In[11], S42, 3174756917); /* 62 */
    II ( c, d, a, b, In[ 2], S43,  718787259); /* 63 */
    II ( b, c, d, a, In[ 9], S44, 3951481745); /* 64 */

    Buffer[0] += a;
    Buffer[1] += b;
    Buffer[2] += c;
    Buffer[3] += d;
}

VOID
MD5Init(
    _Inout_ PMD5_CONTEXT Md5Context
)
/*++

Routine Description:

    Description.

Arguments:

    Md5Context - 

Return Value:

    VOID.

--*/
{
    Md5Context->i[0] = Md5Context->i[1] = (UINT32)0;

    /* Load magic Initialization constants.
     */
    Md5Context->Buffer[0] = (UINT32)0x67452301;
    Md5Context->Buffer[1] = (UINT32)0xefcdab89;
    Md5Context->Buffer[2] = (UINT32)0x98badcfe;
    Md5Context->Buffer[3] = (UINT32)0x10325476;
}

VOID
MD5Update(
    _Inout_ PMD5_CONTEXT Md5Context,
    _In_ PUCHAR InBuf,
    _In_ ULONG InLen
)
/*++

Routine Description:

    Description.

Arguments:

    Md5Context - 
    InBuf - 
    InLen - 

Return Value:

    ULONG64.

--*/
{
    ULONG In[16];
    int Mdi;
    ULONG i, ii;

    /* compute number of bytes mod 64 */
    Mdi = (int)((Md5Context->i[0] >> 3) & 0x3F);

    /* update number of bits */
    if ((Md5Context->i[0] + ((ULONG)InLen << 3)) < Md5Context->i[0])
    Md5Context->i[1]++;
    Md5Context->i[0] += ((ULONG)InLen << 3);
    Md5Context->i[1] += ((ULONG)InLen >> 29);

    while (InLen--)
    {
        /* add new character to Bufferfer, Increment Mdi */
        Md5Context->In[Mdi++] = *InBuf++;

        /* transform if necessary */
        if (Mdi == 0x40)
        {
          for (i = 0, ii = 0; i < 16; i++, ii += 4)
            In[i] = (((ULONG)Md5Context->In[ii+3]) << 24) |
                    (((ULONG)Md5Context->In[ii+2]) << 16) |
                    (((ULONG)Md5Context->In[ii+1]) << 8) |
                    ((ULONG)Md5Context->In[ii]);
          Transform (Md5Context->Buffer, In);
          Mdi = 0;
        }
    }
}

VOID
MD5Final(
    _Inout_ MD5_CONTEXT *Md5Context
)
/*++

Routine Description:

    Description.

Arguments:

    Md5Context - 

Return Value:

    VOID.

--*/
{
    ULONG In[16];
    int Mdi;
    ULONG i, ii;
    ULONG PadLen;

    /* save number of bits */
    In[14] = Md5Context->i[0];
    In[15] = Md5Context->i[1];

    /* compute number of bytes mod 64 */
    Mdi = (int)((Md5Context->i[0] >> 3) & 0x3F);

    /* pad out to 56 mod 64 */
    PadLen = (Mdi < 56) ? (56 - Mdi) : (120 - Mdi);
    MD5Update (Md5Context, PADDING, PadLen);

    /* append length In bits and transform */
    for (i = 0, ii = 0; i < 14; i++, ii += 4)
    In[i] = (((ULONG)Md5Context->In[ii+3]) << 24) |
            (((ULONG)Md5Context->In[ii+2]) << 16) |
            (((ULONG)Md5Context->In[ii+1]) << 8) |
            ((ULONG)Md5Context->In[ii]);
    Transform (Md5Context->Buffer, In);

    /* store Bufferfer In Digest */
    for (i = 0, ii = 0; i < 4; i++, ii += 4)
    {
        Md5Context->Digest[ii] = (UCHAR)(Md5Context->Buffer[i] & 0xFF);
        Md5Context->Digest[ii+1] =
          (UCHAR)((Md5Context->Buffer[i] >> 8) & 0xFF);
        Md5Context->Digest[ii+2] =
          (UCHAR)((Md5Context->Buffer[i] >> 16) & 0xFF);
        Md5Context->Digest[ii+3] =
          (UCHAR)((Md5Context->Buffer[i] >> 24) & 0xFF);
    }
}