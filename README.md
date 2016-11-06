#SwishDbgExt
===========

Incident Response &amp; Digital Forensics Debugging Extension

## TODO
- [ ] Define structures
- [ ] Define Commands
- [ ] Announce feature contest.

## Commands
### !help
Displays information on available extension commands

### !ms_callbacks     
Display callback functions

### !ms_checkcodecave 
Look for used code cave

### !ms_consoles      
Display console command's history 

### !ms_credentials
Display user's credentials (based on gentilwiki's mimikatz) 
### !ms_drivers
Display list of drivers

### !ms_dump
Dump memory space on disk

### !ms_exqueue
Display Ex queued workers

### !ms_fixit
Reset segmentation in WinDbg (Fix "16.kd>")

### !ms_gdt
Display GDT

### !ms_hivelist
Display list of registry hives

### !ms_idt
Display IDT

### !ms_malscore
Analyze a memory space and returns a Malware Score Index (MSI) - (based on Frank Boldewin's work)

### !ms_mbr
Scan Master Boot Record (MBR)

### !ms_netstat
Display network information (sockets, connections, ...)

### !ms_object
Display list of object

### !ms_process
Display list of processes

### !ms_readkcb
Read key control block

### !ms_readknode
Read key node

### !ms_readkvalue
Read key value

### !ms_scanndishook
Scan and display suspicious NDIS hooks

### !ms_services
Display list of services

### !ms_ssdt
Display service descriptor table (SDT) functions

### !ms_store
Display information related to the Store Manager (ReadyBoost)

### !ms_timers
Display list of KTIMER

### !ms_vacbs
Display list of cached VACBs

### !ms_verbose
Turn verbose mode on/off

## Structures
### PEFile
`PEFile` can be either :
- Executable (.exe) `MsProcessObject::_CACHED_PROCESS_OBJECT`
- Dynamic Library (.dll) `MsDllObject::DLL_INFO`
- Driver (.sys) `MsDriverObject::_DRIVER_INFO`

```
        {
            "name": "PEFile",
            "size": 2416,
            "members": [
                {"name": "m_ImageBase", "symTagType": 16, "offset": 0, "locationType": 4, "symBaseType": 7, "size": 8},
                {"name": "m_ImageSize", "symTagType": 16, "offset": 8, "locationType": 4, "symBaseType": 14, "size": 4},
                {"name": "m_CcSections", "symTagType": 11, "offset": 12, "locationType": 4, "udtName": "std::vector<PEFile::_CACHED_SECTION_INFO,std::allocator<PEFile::_CACHED_SECTION_INFO> >", "size": 12},
                {"name": "m_FileVersion", "symTagType": 11, "offset": 24, "locationType": 4, "udtName": "PEFile::_FILE_VERSION", "size": 2048},
                {"name": "m_Image", "symTagType": 11, "offset": 2072, "locationType": 4, "udtName": "PEFile::_IMAGE_DATA", "size": 28},
                {"name": "m_PdbInfo", "symTagType": 11, "offset": 2100, "locationType": 4, "udtName": "PEFile::_PDB_INFO", "size": 284},
                {"name": "m_ObjectPtr", "symTagType": 16, "offset": 2384, "locationType": 4, "symBaseType": 7, "size": 8},
                {"name": "m_Exports", "symTagType": 11, "offset": 2392, "locationType": 4, "udtName": "std::vector<PEFile::_EXPORT_INFO,std::allocator<PEFile::_EXPORT_INFO> >", "size": 12},
                {"name": "m_NumberOfHookedAPIs", "symTagType": 16, "offset": 2404, "locationType": 4, "symBaseType": 14, "size": 4},
                {"name": "m_NumberOfExportedFunctions", "symTagType": 16, "offset": 2408, "locationType": 4, "symBaseType": 14, "size": 4},
                {"name": "RtlGetRessourceData", "symTagType": 13, "offset": 0, "locationType": 1, "symBaseType": 0, "size": 0},
                {"name": "RtlGetExports", "symTagType": 13, "offset": 0, "locationType": 1, "symBaseType": 0, "size": 0},
                {"name": "InitImage", "symTagType": 13, "offset": 0, "locationType": 1, "symBaseType": 0, "size": 0},
                {"name": "RtlGetSections", "symTagType": 13, "offset": 0, "locationType": 1, "symBaseType": 0, "size": 0},
                {"name": "RtlGetFileVersion", "symTagType": 13, "offset": 0, "locationType": 1, "symBaseType": 0, "size": 0},
                {"name": "RtlGetPdbInfo", "symTagType": 13, "offset": 0, "locationType": 1, "symBaseType": 0, "size": 0},
            ]
        },
		
        {
            "name": "PEFile::_EXPORT_INFO",
            "size": 160,
            "members": [
                {"name": "Index", "symTagType": 16, "offset": 0, "locationType": 4, "symBaseType": 14, "size": 4},
                {"name": "Address", "symTagType": 16, "offset": 8, "locationType": 4, "symBaseType": 7, "size": 8},
                {"name": "Ordinal", "symTagType": 16, "offset": 16, "locationType": 4, "symBaseType": 14, "size": 4},
                {"name": "Name", "symTagType": 15, "offset": 20, "locationType": 4, "numberOfElements": 128, "size": 128},
                {"name": "IsTablePatched", "symTagType": 16, "offset": 148, "locationType": 4, "symBaseType": 6, "size": 4},
                {"name": "IsHooked", "symTagType": 16, "offset": 152, "locationType": 4, "symBaseType": 6, "size": 4}
            ]
        },
        {
            "name": "PEFile::_FILE_VERSION",
            "size": 2048,
            "members": [
                {"name": "ProductVersion", "symTagType": 15, "offset": 0, "locationType": 4, "numberOfElements": 256, "size": 512},
                {"name": "FileVersion", "symTagType": 15, "offset": 512, "locationType": 4, "numberOfElements": 256, "size": 512},
                {"name": "CompanyName", "symTagType": 15, "offset": 1024, "locationType": 4, "numberOfElements": 256, "size": 512},
                {"name": "FileDescription", "symTagType": 15, "offset": 1536, "locationType": 4, "numberOfElements": 256, "size": 512}
            ]
        },
        {
            "name": "PEFile::_LANGANDCODEPAGE",
            "size": 4,
            "members": [
                {"name": "wLanguage", "symTagType": 16, "offset": 0, "locationType": 4, "symBaseType": 7, "size": 2},
                {"name": "wCodePage", "symTagType": 16, "offset": 2, "locationType": 4, "symBaseType": 7, "size": 2}
            ]
        },
        {
            "name": "PEFile::_PDB_INFO",
            "size": 284,
            "members": [
                {"name": "Guid", "symTagType": 11, "offset": 0, "locationType": 4, "udtName": "_GUID", "size": 16},
                {"name": "Age", "symTagType": 16, "offset": 16, "locationType": 4, "symBaseType": 14, "size": 4},
                {"name": "PdbName", "symTagType": 15, "offset": 20, "locationType": 4, "numberOfElements": 261, "size": 261}
            ]
        },
        {
            "name": "PEFile::_CACHED_SECTION_INFO",
            "size": 72,
            "members": [
                {"name": "Index", "symTagType": 16, "offset": 0, "locationType": 4, "symBaseType": 14, "size": 4},
                {"name": "Name", "symTagType": 15, "offset": 4, "locationType": 4, "numberOfElements": 9, "size": 9},
                {"name": "VaBase", "symTagType": 16, "offset": 16, "locationType": 4, "symBaseType": 14, "size": 4},
                {"name": "VaSize", "symTagType": 16, "offset": 20, "locationType": 4, "symBaseType": 14, "size": 4},
                {"name": "VaMd5Hash", "symTagType": 15, "offset": 24, "locationType": 4, "numberOfElements": 16, "size": 16},
                {"name": "RawBase", "symTagType": 16, "offset": 40, "locationType": 4, "symBaseType": 14, "size": 4},
                {"name": "RawSize", "symTagType": 16, "offset": 44, "locationType": 4, "symBaseType": 14, "size": 4},
                {"name": "RawMd5Hash", "symTagType": 15, "offset": 48, "locationType": 4, "numberOfElements": 16, "size": 16},
                {"name": "IsExecutable", "symTagType": 16, "offset": 64, "locationType": 4, "symBaseType": 7, "size": 1},
                {"name": "Characteristics", "symTagType": 16, "offset": 68, "locationType": 4, "symBaseType": 7, "size": 4}
            ]
        },
        {
            "name": "PEFile::_IMAGE_DATA",
            "size": 28,
            "members": [
                {"name": "Image", "symTagType": 14, "offset": 0, "locationType": 4, "udtName": "_IMAGE_DOS_HEADER", "size": 4},
                {"name": "NtHeader32", "symTagType": 14, "offset": 4, "locationType": 4, "udtName": "_IMAGE_NT_HEADERS", "size": 4},
                {"name": "NtHeader64", "symTagType": 14, "offset": 8, "locationType": 4, "udtName": "_IMAGE_NT_HEADERS64", "size": 4},
                {"name": "DataDirectory", "symTagType": 14, "offset": 12, "locationType": 4, "udtName": "_IMAGE_DATA_DIRECTORY", "size": 4},
                {"name": "Sections", "symTagType": 14, "offset": 16, "locationType": 4, "udtName": "_IMAGE_SECTION_HEADER", "size": 4},
                {"name": "NumberOfSections", "symTagType": 16, "offset": 20, "locationType": 4, "symBaseType": 14, "size": 4},
                {"name": "Initialized", "symTagType": 16, "offset": 24, "locationType": 4, "symBaseType": 7, "size": 1}
            ]
        },
```