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

    - Storage.h

    Abstract:

    - http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx

    Environment:

    - User mode

    Revision History:

    - Matthieu Suiche

--*/

class StoreManager {
public:
    #define SM_LOG_CTX_OFFSET_X64 0x880
    #define SMC_CACHE_MGR_OFFSET_X64 0x9a0

    #define SM_LOG_CTX_OFFSET_X86 0x510
    #define SMC_CACHE_MGR_OFFSET_X86 0x5b4

    #define SM_LOG_ENTRY32_PAGECOUNT_BITS ((sizeof(ULONG32) * 8) - 16)
    #define SM_LOG_ENTRY64_PAGECOUNT_BITS ((sizeof(ULONG64) * 8) - 16)

    #define SM_STORES_MAX (1 << 3)

    //
    // Structures
    //

    #define SMP_LB_ENTRY_COUNT_BITS 16

    typedef struct _SMC_CACHE {
        ULONG CacheId;
        ULONG u000[3];
        ULONG CacheFileSize;
        ULONG u014[5];
        ULONG FileHandle;
        ULONG FileObject;
        UCHAR u030[0x14c];
        WCHAR UniqueId[256];
    } SMC_CACHE, *PSMC_CACHE;

    typedef struct _SMC_CACHE_REF {
        ULONG_PTR Cache;
        ULONG_PTR RefCount; // not used in sminfo.
        ULONG_PTR AddRemoveLock; // not used in sminfo.
        ULONG SeqNumber; // not used in sminfo.
    } SMC_CACHE_REF, *PSMC_CACHE_REF;

    typedef struct _SMP_LOG_BUFFER32 {
        ULONG32 Link; // SINGLE_LIST_ENTRY
        ULONG EntryCount:SMP_LB_ENTRY_COUNT_BITS;
        ULONG EntryMax:SMP_LB_ENTRY_COUNT_BITS;
    } SMP_LOG_BUFFER32, *PSMP_LOG_BUFFER32;

    typedef struct _SMP_LOG_BUFFER64 {
        ULONG64 Link; // SINGLE_LIST_ENTRY
        ULONG EntryCount:SMP_LB_ENTRY_COUNT_BITS;
        ULONG EntryMax:SMP_LB_ENTRY_COUNT_BITS;
    } SMP_LOG_BUFFER64, *PSMP_LOG_BUFFER64;

    typedef enum _SM_LOG_ENTRY_TYPE {
        SmLogAdd,
        SmLogRemove,
        SmLogFull,
        SmLogStoreUpdate,
        SmLogEntryTypeMax
    } SM_LOG_ENTRY_TYPE, *PSM_LOG_ENTRY_TYPE;

    typedef union _SM_LOG_ENTRY_FLAGS {
        struct {
            ULONG Type:2;
            ULONG Priority:3;
            ULONG DidNotCompress:1;
            ULONG Spare:2;
            ULONG StoreSet:SM_STORES_MAX;
        };

        struct {
            ULONG OverlapsWithType:2;
            ULONG Empty:1;
            ULONG Spare1:5;
            ULONG OverlapsWithStoreSet:SM_STORES_MAX;
        };
    } SM_LOG_ENTRY_FLAGS, *PSM_LOG_ENTRY_FLAGS;

    typedef enum _SM_PAGE_TYPE {
        SmPageTypeProcess = 0,
        SmPageTypeSession,
        SmPageTypeSystem,
        SmPageTypeSection,
        SmPageTypeMax
    } SM_PAGE_TYPE, *PSM_PAGE_TYPE;

    typedef struct _SM_PAGE_KEY_DESCRIPTOR32 {
        union {
            struct {
                ULONG32 ProcessKey;
                ULONG32 VirtualAddress;
            };
            struct {
                ULONG32 PageType:2;
                ULONG32 Spare:1;
            } Flags;
        };
    } SM_PAGE_KEY_DESCRIPTOR32, *PSM_PAGE_KEY_DESCRIPTOR32;

    typedef struct _SM_LOG_ENTRY32 {
        SM_PAGE_KEY_DESCRIPTOR32 KeyDescriptor;
        union {
            SM_LOG_ENTRY_FLAGS Flags;
            struct {
                ULONG32 AllFlags:16;
                ULONG32 PageCount:SM_LOG_ENTRY32_PAGECOUNT_BITS;
            };
        };
    } SM_LOG_ENTRY32, *PSM_LOG_ENTRY32;

    typedef struct _SM_PAGE_KEY_DESCRIPTOR64 {
        union {
            struct {
                ULONG64 ProcessKey;
                ULONG64 VirtualAddress;
            };

            struct {
                ULONG PageType:2;
                ULONG Spare:1;
            } Flags;
        };
    } SM_PAGE_KEY_DESCRIPTOR64, *PSM_PAGE_KEY_DESCRIPTOR64;

    typedef struct _SM_LOG_ENTRY64 {
        SM_PAGE_KEY_DESCRIPTOR64 KeyDescriptor;
        union {
            SM_LOG_ENTRY_FLAGS Flags;
            struct {
                ULONG64 AllFlags:16;
                ULONG64 PageCount:SM_LOG_ENTRY64_PAGECOUNT_BITS;
            };
        };
    } SM_LOG_ENTRY64, *PSM_LOG_ENTRY64;

    vector<SM_LOG_ENTRY64> SmLogEntries;

    StoreManager();

    BOOLEAN GetSmLogEntries();
    BOOL
    SmiDisplayCacheInformation(
        ULONG64 CacheManager,
        ULONG CacheIndex
    );

    VOID
    SmiEnumCaches(
        ULONG CacheIndex
    );

    ULONG m_SmLogCtxOffset;
    ULONG m_SmcCacheMgrOffset;
    ULONG m_SmpLogBufferSize;
    ULONG m_SmLogEntrySize;
    ULONG64 m_SmGlobalsAddress;
};