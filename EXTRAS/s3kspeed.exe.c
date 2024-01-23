typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef int INT_PTR;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

typedef uint UINT;

typedef uint UINT_PTR;

typedef UINT_PTR WPARAM;

typedef long LONG_PTR;

typedef LONG_PTR LPARAM;

typedef INT_PTR (*DLGPROC)(HWND, UINT, WPARAM, LPARAM);

struct HWND__ {
    int unused;
};

typedef struct _cpinfo _cpinfo, *P_cpinfo;

typedef uchar BYTE;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo *LPCPINFO;

typedef ulong DWORD;

typedef int (*FARPROC)(void);

typedef struct tagRECT tagRECT, *PtagRECT;

typedef long LONG;

struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

typedef ushort WORD;

typedef WORD *LPWORD;

typedef int INT;

typedef DWORD *LPDWORD;

typedef LONG_PTR LRESULT;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef struct tagRECT *LPRECT;

typedef int BOOL;

typedef BOOL *LPBOOL;

typedef struct HINSTANCE__ *HINSTANCE;

typedef void *LPCVOID;

typedef void *LPVOID;

typedef HINSTANCE HMODULE;

typedef BYTE *LPBYTE;

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef char CHAR;

typedef CHAR *LPSTR;

typedef void *HANDLE;

struct _STARTUPINFOA {
    DWORD cb;
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _STARTUPINFOA *LPSTARTUPINFOA;

typedef union _union_518 _union_518, *P_union_518;

typedef struct _struct_519 _struct_519, *P_struct_519;

typedef void *PVOID;

struct _struct_519 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_518 {
    struct _struct_519 s;
    PVOID Pointer;
};

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulong ULONG_PTR;

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_518 u;
    HANDLE hEvent;
};

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

typedef struct _FLOATING_SAVE_AREA _FLOATING_SAVE_AREA, *P_FLOATING_SAVE_AREA;

typedef struct _FLOATING_SAVE_AREA FLOATING_SAVE_AREA;

struct _FLOATING_SAVE_AREA {
    DWORD ControlWord;
    DWORD StatusWord;
    DWORD TagWord;
    DWORD ErrorOffset;
    DWORD ErrorSelector;
    DWORD DataOffset;
    DWORD DataSelector;
    BYTE RegisterArea[80];
    DWORD Cr0NpxState;
};

struct _CONTEXT {
    DWORD ContextFlags;
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr6;
    DWORD Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs;
    DWORD SegFs;
    DWORD SegEs;
    DWORD SegDs;
    DWORD Edi;
    DWORD Esi;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Ebp;
    DWORD Eip;
    DWORD SegCs;
    DWORD EFlags;
    DWORD Esp;
    DWORD SegSs;
    BYTE ExtendedRegisters[512];
};

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

typedef wchar_t WCHAR;

typedef CHAR *LPCSTR;

typedef CHAR *LPCH;

typedef WCHAR *LPWCH;

typedef WCHAR *LPCWSTR;

typedef DWORD LCID;

typedef WCHAR *LPWSTR;

typedef CONTEXT *PCONTEXT;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef ULONG_PTR SIZE_T;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef uint size_t;




undefined4 FUN_00401160(HINSTANCE param_1)

{
  DialogBoxParamA(param_1,(LPCSTR)0x65,(HWND)0x0,(DLGPROC)&LAB_00401000,0);
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void entry(void)

{
  byte bVar1;
  DWORD DVar2;
  int iVar3;
  HMODULE pHVar4;
  UINT UVar5;
  byte *pbVar6;
  _STARTUPINFOA local_60;
  undefined *local_1c;
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  byte *pbVar7;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_004040b8;
  puStack_10 = &LAB_004023d8;
  local_14 = ExceptionList;
  local_1c = &stack0xffffff88;
  ExceptionList = &local_14;
  DVar2 = GetVersion();
  _DAT_004074f4 = DVar2 >> 8 & 0xff;
  _DAT_004074f0 = DVar2 & 0xff;
  _DAT_004074ec = _DAT_004074f0 * 0x100 + _DAT_004074f4;
  _DAT_004074e8 = DVar2 >> 0x10;
  iVar3 = FUN_004022a0();
  if (iVar3 == 0) {
    FUN_00401350(0x1c);
  }
  local_8 = 0;
  FUN_004020a0();
  FUN_00402090();
  DAT_004079d4 = (byte *)GetCommandLineA();
  DAT_004074d0 = FUN_00401a50();
  if ((DAT_004074d0 == (undefined4 *)0x0) || (DAT_004079d4 == (byte *)0x0)) {
    FUN_004013b0(0xffffffff);
  }
  FUN_004017a0();
  FUN_004016b0();
  FUN_00401380();
  pbVar6 = DAT_004079d4;
  if (*DAT_004079d4 == 0x22) {
    while( true ) {
      pbVar7 = pbVar6;
      pbVar6 = pbVar7 + 1;
      bVar1 = *pbVar6;
      if ((bVar1 == 0x22) || (bVar1 == 0)) break;
      iVar3 = FUN_00401650((uint)bVar1);
      if (iVar3 != 0) {
        pbVar6 = pbVar7 + 2;
      }
    }
    if (*pbVar6 == 0x22) {
      pbVar6 = pbVar7 + 2;
    }
  }
  else {
    for (; 0x20 < *pbVar6; pbVar6 = pbVar6 + 1) {
    }
  }
  for (; (*pbVar6 != 0 && (*pbVar6 < 0x21)); pbVar6 = pbVar6 + 1) {
  }
  local_60.dwFlags = 0;
  GetStartupInfoA(&local_60);
  pHVar4 = GetModuleHandleA((LPCSTR)0x0);
  UVar5 = FUN_00401160(pHVar4);
  FUN_004013b0(UVar5);
  ExceptionList = local_14;
  return;
}



// Library Function - Single Match
//  __amsg_exit
// 
// Library: Visual Studio 1998 Release

void __cdecl __amsg_exit(int param_1)

{
  if (DAT_004074d8 == 1) {
    FUN_004024b0();
  }
  FUN_004024f0(param_1);
  (*DAT_00405054)(0xff);
  return;
}



void __cdecl FUN_00401350(int param_1)

{
  if (DAT_004074d8 == 1) {
    FUN_004024b0();
  }
  FUN_004024f0(param_1);
                    // WARNING: Subroutine does not return
  ExitProcess(0xff);
}



void FUN_00401380(void)

{
  if (DAT_004079d0 != (code *)0x0) {
    (*DAT_004079d0)();
  }
  FUN_004014a0((undefined **)&DAT_00405008,(undefined **)&DAT_0040500c);
  FUN_004014a0((undefined **)&DAT_00405000,(undefined **)&DAT_00405004);
  return;
}



void __cdecl FUN_004013b0(UINT param_1)

{
  FUN_004013f0(param_1,0,0);
  return;
}



// Library Function - Single Match
//  __exit
// 
// Library: Visual Studio 1998 Release

void __cdecl __exit(int _Code)

{
  FUN_004013f0(_Code,1,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_004013f0(UINT param_1,int param_2,int param_3)

{
  HANDLE hProcess;
  code **ppcVar1;
  code **ppcVar2;
  UINT uExitCode;
  
  if (DAT_00407524 == 1) {
    uExitCode = param_1;
    hProcess = GetCurrentProcess();
    TerminateProcess(hProcess,uExitCode);
  }
  _DAT_00407520 = 1;
  DAT_0040751c = (undefined)param_3;
  if (param_2 == 0) {
    if ((DAT_004079cc != (code **)0x0) &&
       (ppcVar2 = (code **)(DAT_004079c8 + -4), ppcVar1 = DAT_004079cc, DAT_004079cc <= ppcVar2)) {
      do {
        if (*ppcVar2 != (code *)0x0) {
          (**ppcVar2)();
          ppcVar1 = DAT_004079cc;
        }
        ppcVar2 = ppcVar2 + -1;
      } while (ppcVar1 <= ppcVar2);
    }
    FUN_004014a0((undefined **)&DAT_00405010,(undefined **)&DAT_00405014);
  }
  FUN_004014a0((undefined **)&DAT_00405018,(undefined **)&DAT_0040501c);
  if (param_3 == 0) {
    DAT_00407524 = 1;
                    // WARNING: Subroutine does not return
    ExitProcess(param_1);
  }
  return;
}



void __cdecl FUN_004014a0(undefined **param_1,undefined **param_2)

{
  if (param_1 < param_2) {
    do {
      if ((code *)*param_1 != (code *)0x0) {
        (*(code *)*param_1)();
      }
      param_1 = (code **)param_1 + 1;
    } while (param_1 < param_2);
  }
  return;
}



void __cdecl FUN_00401650(uint param_1)

{
  FUN_00401670(param_1,0,4);
  return;
}



undefined4 __cdecl FUN_00401670(uint param_1,uint param_2,byte param_3)

{
  uint uVar1;
  
  if (((&DAT_00407641)[param_1 & 0xff] & param_3) == 0) {
    if (param_2 == 0) {
      uVar1 = 0;
    }
    else {
      uVar1 = *(ushort *)(&DAT_0040529a + (param_1 & 0xff) * 2) & param_2;
    }
    if (uVar1 == 0) {
      return 0;
    }
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004016b0(void)

{
  char cVar1;
  char cVar2;
  int *piVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  char *pcVar7;
  int iVar8;
  undefined4 *puVar9;
  char *pcVar10;
  char *pcVar11;
  undefined4 *puVar12;
  int *local_4;
  
  iVar8 = 0;
  cVar2 = *DAT_004074d0;
  pcVar7 = DAT_004074d0;
  while (cVar2 != '\0') {
    if (cVar2 != '=') {
      iVar8 = iVar8 + 1;
    }
    uVar4 = 0xffffffff;
    pcVar10 = pcVar7;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar2 = *pcVar10;
      pcVar10 = pcVar10 + 1;
    } while (cVar2 != '\0');
    pcVar10 = pcVar7 + ~uVar4;
    pcVar7 = pcVar7 + ~uVar4;
    cVar2 = *pcVar10;
  }
  piVar3 = (int *)FUN_00402720(iVar8 * 4 + 4);
  _DAT_00407504 = piVar3;
  if (piVar3 == (int *)0x0) {
    __amsg_exit(9);
  }
  cVar2 = *DAT_004074d0;
  local_4 = piVar3;
  pcVar7 = DAT_004074d0;
  do {
    if (cVar2 == '\0') {
      FUN_004026d0(DAT_004074d0);
      DAT_004074d0 = (char *)0x0;
      *piVar3 = 0;
      return;
    }
    uVar4 = 0xffffffff;
    pcVar10 = pcVar7;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar1 = *pcVar10;
      pcVar10 = pcVar10 + 1;
    } while (cVar1 != '\0');
    uVar4 = ~uVar4;
    if (cVar2 != '=') {
      iVar8 = FUN_00402720(uVar4);
      *piVar3 = iVar8;
      if (iVar8 == 0) {
        __amsg_exit(9);
      }
      uVar5 = 0xffffffff;
      pcVar10 = pcVar7;
      do {
        pcVar11 = pcVar10;
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        pcVar11 = pcVar10 + 1;
        cVar2 = *pcVar10;
        pcVar10 = pcVar11;
      } while (cVar2 != '\0');
      uVar5 = ~uVar5;
      puVar9 = (undefined4 *)(pcVar11 + -uVar5);
      puVar12 = (undefined4 *)*local_4;
      for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
        *puVar12 = *puVar9;
        puVar9 = puVar9 + 1;
        puVar12 = puVar12 + 1;
      }
      piVar3 = local_4 + 1;
      for (uVar5 = uVar5 & 3; local_4 = piVar3, uVar5 != 0; uVar5 = uVar5 - 1) {
        *(undefined *)puVar12 = *(undefined *)puVar9;
        puVar9 = (undefined4 *)((int)puVar9 + 1);
        puVar12 = (undefined4 *)((int)puVar12 + 1);
      }
    }
    cVar2 = pcVar7[uVar4];
    pcVar7 = pcVar7 + uVar4;
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004017a0(void)

{
  byte **ppbVar1;
  LPSTR *ppCVar2;
  int iStack_8;
  int iStack_4;
  
  GetModuleFileNameA((HMODULE)0x0,(LPSTR)&lpFilename_00407530,0x104);
  _DAT_00407514 = &lpFilename_00407530;
  ppCVar2 = DAT_004079d4;
  if (*(char *)DAT_004079d4 == '\0') {
    ppCVar2 = &lpFilename_00407530;
  }
  FUN_00401840((byte *)ppCVar2,(byte **)0x0,(byte *)0x0,&iStack_8,&iStack_4);
  ppbVar1 = (byte **)FUN_00402720(iStack_4 + iStack_8 * 4);
  if (ppbVar1 == (byte **)0x0) {
    __amsg_exit(8);
  }
  FUN_00401840((byte *)ppCVar2,ppbVar1,(byte *)(ppbVar1 + iStack_8),&iStack_8,&iStack_4);
  _DAT_004074fc = ppbVar1;
  _DAT_004074f8 = iStack_8 + -1;
  return;
}



void __cdecl FUN_00401840(byte *param_1,byte **param_2,byte *param_3,int *param_4,int *param_5)

{
  byte *pbVar1;
  byte bVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  int *piVar6;
  byte *pbVar7;
  uint uVar8;
  
  piVar6 = param_5;
  *param_5 = 0;
  *param_4 = 1;
  if (param_2 != (byte **)0x0) {
    *param_2 = param_3;
    param_2 = param_2 + 1;
  }
  if (*param_1 == 0x22) {
    pbVar7 = param_1 + 1;
    bVar2 = param_1[1];
    while ((bVar2 != 0x22 && (bVar2 != 0))) {
      if ((((&DAT_00407641)[bVar2] & 4) != 0) && (*param_5 = *param_5 + 1, param_3 != (byte *)0x0))
      {
        *param_3 = *pbVar7;
        param_3 = param_3 + 1;
        pbVar7 = pbVar7 + 1;
      }
      *param_5 = *param_5 + 1;
      if (param_3 != (byte *)0x0) {
        *param_3 = *pbVar7;
        param_3 = param_3 + 1;
      }
      pbVar1 = pbVar7 + 1;
      pbVar7 = pbVar7 + 1;
      bVar2 = *pbVar1;
    }
    *param_5 = *param_5 + 1;
    if (param_3 != (byte *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    if (*pbVar7 == 0x22) {
      pbVar7 = pbVar7 + 1;
    }
  }
  else {
    do {
      *piVar6 = *piVar6 + 1;
      if (param_3 != (byte *)0x0) {
        *param_3 = *param_1;
        param_3 = param_3 + 1;
      }
      bVar2 = *param_1;
      pbVar7 = param_1 + 1;
      param_5 = (int *)(uint)bVar2;
      if ((*(byte *)((int)param_5 + 0x407641) & 4) != 0) {
        *piVar6 = *piVar6 + 1;
        if (param_3 != (byte *)0x0) {
          *param_3 = *pbVar7;
          param_3 = param_3 + 1;
        }
        pbVar7 = param_1 + 2;
      }
      if (bVar2 == 0x20) break;
      if (bVar2 == 0) goto LAB_00401919;
      param_1 = pbVar7;
    } while (bVar2 != 9);
    if (bVar2 == 0) {
LAB_00401919:
      pbVar7 = pbVar7 + -1;
    }
    else if (param_3 != (byte *)0x0) {
      param_3[-1] = 0;
    }
  }
  bVar4 = false;
  bVar5 = false;
  while (*pbVar7 != 0) {
    for (; (*pbVar7 == 0x20 || (*pbVar7 == 9)); pbVar7 = pbVar7 + 1) {
    }
    if (*pbVar7 == 0) break;
    if (param_2 != (byte **)0x0) {
      *param_2 = param_3;
      param_2 = param_2 + 1;
    }
    *param_4 = *param_4 + 1;
    while( true ) {
      uVar8 = 0;
      bVar3 = true;
      bVar2 = *pbVar7;
      while (bVar2 == 0x5c) {
        pbVar1 = pbVar7 + 1;
        pbVar7 = pbVar7 + 1;
        uVar8 = uVar8 + 1;
        bVar2 = *pbVar1;
      }
      if (*pbVar7 == 0x22) {
        if ((uVar8 & 1) == 0) {
          if ((bVar4) && (pbVar7[1] == 0x22)) {
            pbVar7 = pbVar7 + 1;
          }
          else {
            bVar3 = false;
          }
          bVar4 = !bVar5;
          bVar5 = bVar4;
        }
        uVar8 = uVar8 >> 1;
      }
      for (; uVar8 != 0; uVar8 = uVar8 - 1) {
        if (param_3 != (byte *)0x0) {
          *param_3 = 0x5c;
          param_3 = param_3 + 1;
        }
        *piVar6 = *piVar6 + 1;
      }
      bVar2 = *pbVar7;
      if ((bVar2 == 0) || ((!bVar4 && ((bVar2 == 0x20 || (bVar2 == 9)))))) break;
      if (bVar3) {
        if (param_3 == (byte *)0x0) {
          if (((&DAT_00407641)[bVar2] & 4) != 0) {
            pbVar7 = pbVar7 + 1;
            *piVar6 = *piVar6 + 1;
          }
          *piVar6 = *piVar6 + 1;
          goto LAB_00401a15;
        }
        if (((&DAT_00407641)[bVar2] & 4) != 0) {
          *param_3 = bVar2;
          param_3 = param_3 + 1;
          pbVar7 = pbVar7 + 1;
          *piVar6 = *piVar6 + 1;
        }
        *param_3 = *pbVar7;
        param_3 = param_3 + 1;
        *piVar6 = *piVar6 + 1;
        pbVar7 = pbVar7 + 1;
      }
      else {
LAB_00401a15:
        pbVar7 = pbVar7 + 1;
      }
    }
    if (param_3 != (byte *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    *piVar6 = *piVar6 + 1;
  }
  if (param_2 != (byte **)0x0) {
    *param_2 = (byte *)0x0;
  }
  *param_4 = *param_4 + 1;
  return;
}



undefined4 * FUN_00401a50(void)

{
  char cVar1;
  WCHAR WVar2;
  WCHAR *pWVar3;
  int iVar5;
  uint uVar6;
  undefined4 *puVar7;
  uint uVar8;
  undefined4 *puVar9;
  LPWCH lpWideCharStr;
  undefined4 *puVar10;
  undefined4 *puVar11;
  WCHAR *pWVar4;
  
  lpWideCharStr = (LPWCH)0x0;
  puVar9 = (undefined4 *)0x0;
  if (DAT_00407638 == 0) {
    lpWideCharStr = GetEnvironmentStringsW();
    if (lpWideCharStr == (LPWCH)0x0) {
      puVar9 = (undefined4 *)GetEnvironmentStrings();
      if (puVar9 == (undefined4 *)0x0) {
        return (undefined4 *)0x0;
      }
      DAT_00407638 = 2;
    }
    else {
      DAT_00407638 = 1;
    }
  }
  if (DAT_00407638 == 1) {
    if ((lpWideCharStr != (LPWCH)0x0) ||
       (lpWideCharStr = GetEnvironmentStringsW(), lpWideCharStr != (LPWCH)0x0)) {
      WVar2 = *lpWideCharStr;
      pWVar3 = lpWideCharStr;
      while (WVar2 != L'\0') {
        do {
          pWVar4 = pWVar3;
          pWVar3 = pWVar4 + 1;
        } while (*pWVar3 != L'\0');
        pWVar3 = pWVar4 + 2;
        WVar2 = *pWVar3;
      }
      iVar5 = ((int)pWVar3 - (int)lpWideCharStr >> 1) + 1;
      uVar6 = WideCharToMultiByte(0,0,lpWideCharStr,iVar5,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0);
      if ((uVar6 != 0) && (puVar9 = (undefined4 *)FUN_00402720(uVar6), puVar9 != (undefined4 *)0x0))
      {
        iVar5 = WideCharToMultiByte(0,0,lpWideCharStr,iVar5,(LPSTR)puVar9,uVar6,(LPCSTR)0x0,
                                    (LPBOOL)0x0);
        if (iVar5 == 0) {
          FUN_004026d0(puVar9);
          puVar9 = (undefined4 *)0x0;
        }
        FreeEnvironmentStringsW(lpWideCharStr);
        return puVar9;
      }
      FreeEnvironmentStringsW(lpWideCharStr);
      return (undefined4 *)0x0;
    }
  }
  else if ((DAT_00407638 == 2) &&
          ((puVar9 != (undefined4 *)0x0 ||
           (puVar9 = (undefined4 *)GetEnvironmentStrings(), puVar9 != (undefined4 *)0x0)))) {
    cVar1 = *(char *)puVar9;
    puVar7 = puVar9;
    while (cVar1 != '\0') {
      do {
        puVar10 = puVar7;
        puVar7 = (undefined4 *)((int)puVar10 + 1);
      } while (*(char *)((int)puVar10 + 1) != '\0');
      puVar7 = (undefined4 *)((int)puVar10 + 2);
      cVar1 = *(char *)((int)puVar10 + 2);
    }
    uVar6 = (int)puVar7 + (1 - (int)puVar9);
    puVar7 = (undefined4 *)FUN_00402720(uVar6);
    if (puVar7 != (undefined4 *)0x0) {
      puVar10 = puVar9;
      puVar11 = puVar7;
      for (uVar8 = uVar6 >> 2; uVar8 != 0; uVar8 = uVar8 - 1) {
        *puVar11 = *puVar10;
        puVar10 = puVar10 + 1;
        puVar11 = puVar11 + 1;
      }
      for (uVar6 = uVar6 & 3; uVar6 != 0; uVar6 = uVar6 - 1) {
        *(undefined *)puVar11 = *(undefined *)puVar10;
        puVar10 = (undefined4 *)((int)puVar10 + 1);
        puVar11 = (undefined4 *)((int)puVar11 + 1);
      }
      FreeEnvironmentStringsA((LPCH)puVar9);
      return puVar7;
    }
    FreeEnvironmentStringsA((LPCH)puVar9);
    return (undefined4 *)0x0;
  }
  return (undefined4 *)0x0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_00401bb0(int param_1)

{
  BYTE *pBVar1;
  byte bVar2;
  byte bVar3;
  UINT CodePage;
  UINT *pUVar4;
  BOOL BVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  BYTE *pBVar10;
  byte *pbVar11;
  byte *pbVar12;
  undefined4 *puVar13;
  _cpinfo local_14;
  
  CodePage = FUN_00401dc0(param_1);
  if (CodePage == DAT_00407848) {
    return 0;
  }
  if (CodePage == 0) {
    FUN_00401e70();
    FUN_00401eb0();
    return 0;
  }
  iVar9 = 0;
  pUVar4 = &DAT_004050f0;
  do {
    if (*pUVar4 == CodePage) {
      puVar13 = (undefined4 *)&DAT_00407640;
      for (iVar8 = 0x40; iVar8 != 0; iVar8 = iVar8 + -1) {
        *puVar13 = 0;
        puVar13 = puVar13 + 1;
      }
      *(undefined *)puVar13 = 0;
      uVar6 = 0;
      pbVar11 = &DAT_00405100 + iVar9 * 0x30;
      do {
        bVar2 = *pbVar11;
        for (pbVar12 = pbVar11; (bVar2 != 0 && (bVar2 = pbVar12[1], bVar2 != 0));
            pbVar12 = pbVar12 + 2) {
          uVar7 = (uint)*pbVar12;
          if (uVar7 <= bVar2) {
            bVar3 = (&DAT_004050e8)[uVar6];
            do {
              (&DAT_00407641)[uVar7] = (&DAT_00407641)[uVar7] | bVar3;
              uVar7 = uVar7 + 1;
            } while (uVar7 <= bVar2);
          }
          bVar2 = pbVar12[2];
        }
        uVar6 = uVar6 + 1;
        pbVar11 = pbVar11 + 8;
      } while (uVar6 < 4);
      _DAT_004079c4 = 1;
      DAT_00407848 = CodePage;
      DAT_0040784c = FUN_00401e10(CodePage);
      _DAT_00407850 = (&DAT_004050f4)[iVar9 * 0xc];
      _DAT_00407854 = (&DAT_004050f8)[iVar9 * 0xc];
      _DAT_00407858 = (&DAT_004050fc)[iVar9 * 0xc];
      FUN_00401eb0();
      return 0;
    }
    pUVar4 = pUVar4 + 0xc;
    iVar9 = iVar9 + 1;
  } while (pUVar4 < &DAT_004051e0);
  BVar5 = GetCPInfo(CodePage,&local_14);
  if (BVar5 != 1) {
    if (DAT_0040785c == 0) {
      return 0xffffffff;
    }
    FUN_00401e70();
    FUN_00401eb0();
    return 0;
  }
  puVar13 = (undefined4 *)&DAT_00407640;
  for (iVar9 = 0x40; iVar9 != 0; iVar9 = iVar9 + -1) {
    *puVar13 = 0;
    puVar13 = puVar13 + 1;
  }
  *(undefined *)puVar13 = 0;
  DAT_0040784c = 0;
  if (local_14.MaxCharSize < 2) {
    _DAT_004079c4 = 0;
    DAT_00407848 = CodePage;
  }
  else {
    DAT_00407848 = CodePage;
    if (local_14.LeadByte[0] != '\0') {
      pBVar10 = local_14.LeadByte + 1;
      do {
        bVar2 = *pBVar10;
        if (bVar2 == 0) break;
        for (uVar6 = (uint)pBVar10[-1]; uVar6 <= bVar2; uVar6 = uVar6 + 1) {
          (&DAT_00407641)[uVar6] = (&DAT_00407641)[uVar6] | 4;
        }
        pBVar1 = pBVar10 + 1;
        pBVar10 = pBVar10 + 2;
      } while (*pBVar1 != 0);
    }
    uVar6 = 1;
    do {
      (&DAT_00407641)[uVar6] = (&DAT_00407641)[uVar6] | 8;
      uVar6 = uVar6 + 1;
    } while (uVar6 < 0xff);
    DAT_0040784c = FUN_00401e10(CodePage);
    _DAT_004079c4 = 1;
  }
  _DAT_00407850 = 0;
  _DAT_00407854 = 0;
  _DAT_00407858 = 0;
  FUN_00401eb0();
  return 0;
}



int __cdecl FUN_00401dc0(int param_1)

{
  int iVar1;
  bool bVar2;
  
  if (param_1 == -2) {
    DAT_0040785c = 1;
                    // WARNING: Could not recover jumptable at 0x00401ddd. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetOEMCP();
    return iVar1;
  }
  if (param_1 == -3) {
    DAT_0040785c = 1;
                    // WARNING: Could not recover jumptable at 0x00401df2. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetACP();
    return iVar1;
  }
  bVar2 = param_1 == -4;
  if (bVar2) {
    param_1 = DAT_00407880;
  }
  DAT_0040785c = (uint)bVar2;
  return param_1;
}



undefined4 __cdecl FUN_00401e10(undefined4 param_1)

{
  switch(param_1) {
  case 0x3a4:
    return 0x411;
  default:
    return 0;
  case 0x3a8:
    return 0x804;
  case 0x3b5:
    return 0x412;
  case 0x3b6:
    return 0x404;
  }
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00401e70(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)&DAT_00407640;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined *)puVar2 = 0;
  DAT_00407848 = 0;
  _DAT_004079c4 = 0;
  DAT_0040784c = 0;
  _DAT_00407850 = 0;
  _DAT_00407854 = 0;
  _DAT_00407858 = 0;
  return;
}



void FUN_00401eb0(void)

{
  BOOL BVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  BYTE *pBVar5;
  ushort *puVar6;
  undefined4 *puVar7;
  _cpinfo local_514;
  undefined4 auStack_500 [64];
  WCHAR aWStack_400 [128];
  WCHAR aWStack_300 [128];
  WORD aWStack_200 [256];
  
  BVar1 = GetCPInfo(DAT_00407848,&local_514);
  if (BVar1 == 1) {
    uVar2 = 0;
    do {
      *(char *)((int)auStack_500 + uVar2) = (char)uVar2;
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x100);
    auStack_500[0]._0_1_ = 0x20;
    if (local_514.LeadByte[0] != 0) {
      pBVar5 = local_514.LeadByte + 1;
      do {
        uVar2 = (uint)local_514.LeadByte[0];
        if (uVar2 <= *pBVar5) {
          uVar3 = (*pBVar5 - uVar2) + 1;
          puVar7 = (undefined4 *)((int)auStack_500 + uVar2);
          for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
            *puVar7 = 0x20202020;
            puVar7 = puVar7 + 1;
          }
          for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
            *(undefined *)puVar7 = 0x20;
            puVar7 = (undefined4 *)((int)puVar7 + 1);
          }
        }
        local_514.LeadByte[0] = pBVar5[1];
        pBVar5 = pBVar5 + 2;
      } while (local_514.LeadByte[0] != 0);
    }
    FUN_00402a30(1,(LPCSTR)auStack_500,0x100,aWStack_200,DAT_00407848,DAT_0040784c,0);
    FUN_004027d0(DAT_0040784c,0x100,(char *)auStack_500,(LPCWSTR)0x100,aWStack_400,0x100,
                 DAT_00407848,0);
    FUN_004027d0(DAT_0040784c,0x200,(char *)auStack_500,(LPCWSTR)0x100,aWStack_300,0x100,
                 DAT_00407848,0);
    uVar2 = 0;
    puVar6 = aWStack_200;
    do {
      if ((*puVar6 & 1) == 0) {
        if ((*puVar6 & 2) == 0) {
          (&DAT_00407748)[uVar2] = 0;
        }
        else {
          (&DAT_00407641)[uVar2] = (&DAT_00407641)[uVar2] | 0x20;
          (&DAT_00407748)[uVar2] = *(undefined *)((int)aWStack_300 + uVar2);
        }
      }
      else {
        (&DAT_00407641)[uVar2] = (&DAT_00407641)[uVar2] | 0x10;
        (&DAT_00407748)[uVar2] = *(undefined *)((int)aWStack_400 + uVar2);
      }
      uVar2 = uVar2 + 1;
      puVar6 = puVar6 + 1;
    } while (uVar2 < 0x100);
    return;
  }
  uVar2 = 0;
  do {
    if ((uVar2 < 0x41) || (0x5a < uVar2)) {
      if ((uVar2 < 0x61) || (0x7a < uVar2)) {
        (&DAT_00407748)[uVar2] = 0;
      }
      else {
        (&DAT_00407641)[uVar2] = (&DAT_00407641)[uVar2] | 0x20;
        (&DAT_00407748)[uVar2] = (char)uVar2 + -0x20;
      }
    }
    else {
      (&DAT_00407641)[uVar2] = (&DAT_00407641)[uVar2] | 0x10;
      (&DAT_00407748)[uVar2] = (char)uVar2 + ' ';
    }
    uVar2 = uVar2 + 1;
  } while (uVar2 < 0x100);
  return;
}



void FUN_00402090(void)

{
  FUN_00401bb0(-3);
  return;
}



void FUN_004020a0(void)

{
  byte bVar1;
  undefined4 *puVar2;
  DWORD DVar3;
  HANDLE hFile;
  int iVar4;
  HANDLE *ppvVar5;
  int *piVar6;
  uint uVar7;
  UINT *pUVar8;
  UINT UStack_48;
  _STARTUPINFOA local_44;
  
  puVar2 = (undefined4 *)FUN_00402720(0x100);
  if (puVar2 == (undefined4 *)0x0) {
    __amsg_exit(0x1b);
  }
  DAT_004079c0 = 0x20;
  DAT_004078c0 = puVar2;
  if (puVar2 < puVar2 + 0x40) {
    do {
      *(undefined *)(puVar2 + 1) = 0;
      *puVar2 = 0xffffffff;
      *(undefined *)((int)puVar2 + 5) = 10;
      puVar2 = puVar2 + 2;
    } while (puVar2 < DAT_004078c0 + 0x40);
  }
  GetStartupInfoA(&local_44);
  if ((local_44.cbReserved2 != 0) && ((UINT *)local_44.lpReserved2 != (UINT *)0x0)) {
    UStack_48 = *(UINT *)local_44.lpReserved2;
    pUVar8 = (UINT *)((int)local_44.lpReserved2 + 4);
    ppvVar5 = (HANDLE *)((int)pUVar8 + UStack_48);
    if (0x7ff < (int)UStack_48) {
      UStack_48 = 0x800;
    }
    if ((int)DAT_004079c0 < (int)UStack_48) {
      piVar6 = &DAT_004078c4;
      do {
        puVar2 = (undefined4 *)FUN_00402720(0x100);
        if (puVar2 == (undefined4 *)0x0) {
          UStack_48 = DAT_004079c0;
          break;
        }
        *piVar6 = (int)puVar2;
        DAT_004079c0 = DAT_004079c0 + 0x20;
        if (puVar2 < puVar2 + 0x40) {
          do {
            *(undefined *)(puVar2 + 1) = 0;
            *puVar2 = 0xffffffff;
            *(undefined *)((int)puVar2 + 5) = 10;
            puVar2 = puVar2 + 2;
          } while (puVar2 < (undefined4 *)(*piVar6 + 0x100));
        }
        piVar6 = piVar6 + 1;
      } while ((int)DAT_004079c0 < (int)UStack_48);
    }
    uVar7 = 0;
    if (0 < (int)UStack_48) {
      do {
        if (((*ppvVar5 != (HANDLE)0xffffffff) && ((*(byte *)pUVar8 & 1) != 0)) &&
           (((*(byte *)pUVar8 & 8) != 0 || (DVar3 = GetFileType(*ppvVar5), DVar3 != 0)))) {
          iVar4 = (int)(&DAT_004078c0)[(int)uVar7 >> 5];
          *(HANDLE *)(iVar4 + (uVar7 & 0x1f) * 8) = *ppvVar5;
          *(byte *)(iVar4 + (uVar7 & 0x1f) * 8 + 4) = *(byte *)pUVar8;
        }
        uVar7 = uVar7 + 1;
        pUVar8 = (UINT *)((int)pUVar8 + 1);
        ppvVar5 = ppvVar5 + 1;
      } while ((int)uVar7 < (int)UStack_48);
    }
  }
  iVar4 = 0;
  do {
    ppvVar5 = (HANDLE *)(DAT_004078c0 + iVar4 * 2);
    if (DAT_004078c0[iVar4 * 2] == -1) {
      *(undefined *)(ppvVar5 + 1) = 0x81;
      if (iVar4 == 0) {
        DVar3 = 0xfffffff6;
      }
      else {
        DVar3 = 0xfffffff5 - (iVar4 != 1);
      }
      hFile = GetStdHandle(DVar3);
      if ((hFile == (HANDLE)0xffffffff) || (DVar3 = GetFileType(hFile), DVar3 == 0)) {
        bVar1 = *(byte *)(ppvVar5 + 1) | 0x40;
        goto LAB_0040227b;
      }
      *ppvVar5 = hFile;
      if ((DVar3 & 0xff) == 2) {
        bVar1 = *(byte *)(ppvVar5 + 1) | 0x40;
        goto LAB_0040227b;
      }
      if ((DVar3 & 0xff) == 3) {
        bVar1 = *(byte *)(ppvVar5 + 1) | 8;
        goto LAB_0040227b;
      }
    }
    else {
      bVar1 = *(byte *)(ppvVar5 + 1) | 0x80;
LAB_0040227b:
      *(byte *)(ppvVar5 + 1) = bVar1;
    }
    iVar4 = iVar4 + 1;
    if (2 < iVar4) {
      SetHandleCount(DAT_004079c0);
      return;
    }
  } while( true );
}



undefined4 FUN_004022a0(void)

{
  undefined4 *puVar1;
  
  DAT_004078ac = HeapCreate(1,0x1000,0);
  if (DAT_004078ac == (HANDLE)0x0) {
    return 0;
  }
  puVar1 = FUN_00402b70();
  if (puVar1 == (undefined4 *)0x0) {
    HeapDestroy(DAT_004078ac);
    return 0;
  }
  return 1;
}



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __cdecl __global_unwind2(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x4022f8,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
  return;
}



// Library Function - Single Match
//  __local_unwind2
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release, Visual Studio 2003 Debug, Visual
// Studio 2003 Release

void __cdecl __local_unwind2(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  void *pvStack_1c;
  undefined *puStack_18;
  undefined4 local_14;
  int iStack_10;
  
  iStack_10 = param_1;
  puStack_18 = &LAB_00402300;
  pvStack_1c = ExceptionList;
  ExceptionList = &pvStack_1c;
  while( true ) {
    iVar1 = *(int *)(param_1 + 8);
    iVar2 = *(int *)(param_1 + 0xc);
    if ((iVar2 == -1) || (iVar2 == param_2)) break;
    local_14 = *(undefined4 *)(iVar1 + iVar2 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_14;
    if (*(int *)(iVar1 + 4 + iVar2 * 0xc) == 0) {
      FUN_004023b6();
      (**(code **)(iVar1 + 8 + iVar2 * 0xc))();
    }
  }
  ExceptionList = pvStack_1c;
  return;
}



void FUN_004023b6(void)

{
  undefined4 in_EAX;
  int unaff_EBP;
  
  DAT_004051f4 = *(undefined4 *)(unaff_EBP + 8);
  DAT_004051f0 = in_EAX;
  DAT_004051f8 = unaff_EBP;
  return;
}



void FUN_00402495(int param_1)

{
  __local_unwind2(*(int *)(param_1 + 0x18),*(int *)(param_1 + 0x1c));
  return;
}



void FUN_004024b0(void)

{
  if ((DAT_004074d8 == 1) || ((DAT_004074d8 == 0 && (DAT_00405058 == 1)))) {
    FUN_004024f0(0xfc);
    if (DAT_00407860 != (code *)0x0) {
      (*DAT_00407860)();
    }
    FUN_004024f0(0xff);
  }
  return;
}



void __cdecl FUN_004024f0(int param_1)

{
  char cVar1;
  int *piVar2;
  DWORD DVar3;
  HANDLE hFile;
  int iVar4;
  uint uVar5;
  uint uVar6;
  undefined4 *puVar7;
  int iVar8;
  undefined4 *puVar9;
  undefined4 *puVar10;
  char *pcVar11;
  char *pcVar12;
  DWORD local_1a8;
  undefined4 auStack_1a4 [25];
  undefined4 auStack_140 [15];
  undefined4 local_104;
  
  piVar2 = &DAT_00405200;
  iVar8 = 0;
  do {
    if (param_1 == *piVar2) break;
    piVar2 = piVar2 + 2;
    iVar8 = iVar8 + 1;
  } while (piVar2 < &DAT_00405290);
  if (param_1 == (&DAT_00405200)[iVar8 * 2]) {
    if ((DAT_004074d8 == 1) || ((DAT_004074d8 == 0 && (DAT_00405058 == 1)))) {
      if ((DAT_004078c0 == 0) ||
         (hFile = *(HANDLE *)(DAT_004078c0 + 0x10), hFile == (HANDLE)0xffffffff)) {
        hFile = GetStdHandle(0xfffffff4);
      }
      pcVar11 = *(char **)(iVar8 * 8 + 0x405204);
      uVar5 = 0xffffffff;
      pcVar12 = pcVar11;
      do {
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        cVar1 = *pcVar12;
        pcVar12 = pcVar12 + 1;
      } while (cVar1 != '\0');
      WriteFile(hFile,pcVar11,~uVar5 - 1,&local_1a8,(LPOVERLAPPED)0x0);
    }
    else if (param_1 != 0xfc) {
      DVar3 = GetModuleFileNameA((HMODULE)0x0,(LPSTR)&local_104,0x104);
      if (DVar3 == 0) {
        puVar7 = (undefined4 *)"<program name unknown>";
        puVar9 = &local_104;
        for (iVar4 = 5; iVar4 != 0; iVar4 = iVar4 + -1) {
          *puVar9 = *puVar7;
          puVar7 = puVar7 + 1;
          puVar9 = puVar9 + 1;
        }
        *(undefined2 *)puVar9 = *(undefined2 *)puVar7;
        *(undefined *)((int)puVar9 + 2) = *(undefined *)((int)puVar7 + 2);
      }
      uVar5 = 0xffffffff;
      puVar7 = &local_104;
      puVar9 = &local_104;
      do {
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        cVar1 = *(char *)puVar9;
        puVar9 = (undefined4 *)((int)puVar9 + 1);
      } while (cVar1 != '\0');
      if (0x3c < ~uVar5) {
        uVar5 = 0xffffffff;
        puVar7 = &local_104;
        do {
          if (uVar5 == 0) break;
          uVar5 = uVar5 - 1;
          cVar1 = *(char *)puVar7;
          puVar7 = (undefined4 *)((int)puVar7 + 1);
        } while (cVar1 != '\0');
        puVar7 = (undefined4 *)((int)auStack_140 + ~uVar5);
        _strncpy((char *)puVar7,"...",3);
      }
      puVar9 = (undefined4 *)"Runtime Error!\n\nProgram: ";
      puVar10 = auStack_1a4;
      for (iVar4 = 6; iVar4 != 0; iVar4 = iVar4 + -1) {
        *puVar10 = *puVar9;
        puVar9 = puVar9 + 1;
        puVar10 = puVar10 + 1;
      }
      *(undefined2 *)puVar10 = *(undefined2 *)puVar9;
      uVar5 = 0xffffffff;
      do {
        puVar9 = puVar7;
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        puVar9 = (undefined4 *)((int)puVar7 + 1);
        cVar1 = *(char *)puVar7;
        puVar7 = puVar9;
      } while (cVar1 != '\0');
      uVar5 = ~uVar5;
      iVar4 = -1;
      puVar7 = auStack_1a4;
      do {
        puVar10 = puVar7;
        if (iVar4 == 0) break;
        iVar4 = iVar4 + -1;
        puVar10 = (undefined4 *)((int)puVar7 + 1);
        cVar1 = *(char *)puVar7;
        puVar7 = puVar10;
      } while (cVar1 != '\0');
      puVar7 = (undefined4 *)((int)puVar9 - uVar5);
      puVar9 = (undefined4 *)((int)puVar10 + -1);
      for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
        *puVar9 = *puVar7;
        puVar7 = puVar7 + 1;
        puVar9 = puVar9 + 1;
      }
      for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
        *(undefined *)puVar9 = *(undefined *)puVar7;
        puVar7 = (undefined4 *)((int)puVar7 + 1);
        puVar9 = (undefined4 *)((int)puVar9 + 1);
      }
      uVar5 = 0xffffffff;
      pcVar11 = "\n\n";
      do {
        pcVar12 = pcVar11;
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        pcVar12 = pcVar11 + 1;
        cVar1 = *pcVar11;
        pcVar11 = pcVar12;
      } while (cVar1 != '\0');
      uVar5 = ~uVar5;
      iVar4 = -1;
      puVar7 = auStack_1a4;
      do {
        puVar9 = puVar7;
        if (iVar4 == 0) break;
        iVar4 = iVar4 + -1;
        puVar9 = (undefined4 *)((int)puVar7 + 1);
        cVar1 = *(char *)puVar7;
        puVar7 = puVar9;
      } while (cVar1 != '\0');
      puVar7 = (undefined4 *)(pcVar12 + -uVar5);
      puVar9 = (undefined4 *)((int)puVar9 + -1);
      for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
        *puVar9 = *puVar7;
        puVar7 = puVar7 + 1;
        puVar9 = puVar9 + 1;
      }
      for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
        *(undefined *)puVar9 = *(undefined *)puVar7;
        puVar7 = (undefined4 *)((int)puVar7 + 1);
        puVar9 = (undefined4 *)((int)puVar9 + 1);
      }
      uVar5 = 0xffffffff;
      pcVar11 = *(char **)(iVar8 * 8 + 0x405204);
      do {
        pcVar12 = pcVar11;
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        pcVar12 = pcVar11 + 1;
        cVar1 = *pcVar11;
        pcVar11 = pcVar12;
      } while (cVar1 != '\0');
      uVar5 = ~uVar5;
      iVar8 = -1;
      puVar7 = auStack_1a4;
      do {
        puVar9 = puVar7;
        if (iVar8 == 0) break;
        iVar8 = iVar8 + -1;
        puVar9 = (undefined4 *)((int)puVar7 + 1);
        cVar1 = *(char *)puVar7;
        puVar7 = puVar9;
      } while (cVar1 != '\0');
      puVar7 = (undefined4 *)(pcVar12 + -uVar5);
      puVar9 = (undefined4 *)((int)puVar9 + -1);
      for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
        *puVar9 = *puVar7;
        puVar7 = puVar7 + 1;
        puVar9 = puVar9 + 1;
      }
      for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
        *(undefined *)puVar9 = *(undefined *)puVar7;
        puVar7 = (undefined4 *)((int)puVar7 + 1);
        puVar9 = (undefined4 *)((int)puVar9 + 1);
      }
      FUN_00403290(auStack_1a4,"Microsoft Visual C++ Runtime Library",0x12010);
      return;
    }
  }
  return;
}



void __cdecl FUN_004026d0(LPVOID param_1)

{
  LPVOID lpMem;
  byte *pbVar1;
  int local_4;
  
  lpMem = param_1;
  if (param_1 != (LPVOID)0x0) {
    pbVar1 = (byte *)FUN_00402e10((uint)param_1,&local_4,(uint *)&param_1);
    if (pbVar1 != (byte *)0x0) {
      FUN_00402e70(local_4,(int)param_1,pbVar1);
      return;
    }
    HeapFree(DAT_004078ac,0,lpMem);
  }
  return;
}



void __cdecl FUN_00402720(uint param_1)

{
  FUN_00402740(param_1,DAT_004078a4);
  return;
}



int __cdecl FUN_00402740(uint param_1,int param_2)

{
  int iVar1;
  
  if (param_1 < 0xffffffe1) {
    if (param_1 == 0) {
      param_1 = 1;
    }
    do {
      if (param_1 < 0xffffffe1) {
        iVar1 = FUN_00402790(param_1);
      }
      else {
        iVar1 = 0;
      }
      if (iVar1 != 0) {
        return iVar1;
      }
      if (param_2 == 0) {
        return 0;
      }
      iVar1 = FUN_00403420(param_1);
    } while (iVar1 != 0);
  }
  return 0;
}



void __cdecl FUN_00402790(int param_1)

{
  int *piVar1;
  uint dwBytes;
  
  dwBytes = param_1 + 0xfU & 0xfffffff0;
  if ((dwBytes <= DAT_004074c4) &&
     (piVar1 = FUN_00402ed0((int *)(param_1 + 0xfU >> 4)), piVar1 != (int *)0x0)) {
    return;
  }
  HeapAlloc(DAT_004078ac,0,dwBytes);
  return;
}



int __cdecl
FUN_004027d0(LCID param_1,uint param_2,char *param_3,LPCWSTR param_4,LPWSTR param_5,int param_6,
            UINT param_7,int param_8)

{
  int iVar1;
  LPCWSTR cbMultiByte;
  LPCWSTR lpWideCharStr;
  int iVar2;
  
  if (DAT_00407888 == 0) {
    iVar1 = LCMapStringW(0,0x100,(LPCWSTR)&lpSrcStr_004043b8,1,(LPWSTR)0x0,0);
    if (iVar1 == 0) {
      iVar1 = LCMapStringA(0,0x100,(LPCSTR)&lpSrcStr_004043b4,1,(LPSTR)0x0,0);
      if (iVar1 == 0) {
        return 0;
      }
      DAT_00407888 = 2;
    }
    else {
      DAT_00407888 = 1;
    }
  }
  cbMultiByte = param_4;
  if (0 < (int)param_4) {
    cbMultiByte = (LPCWSTR)FUN_00402a00(param_3,(int)param_4);
  }
  if (DAT_00407888 == 2) {
    iVar1 = LCMapStringA(param_1,param_2,param_3,(int)cbMultiByte,(LPSTR)param_5,param_6);
    return iVar1;
  }
  if (DAT_00407888 != 1) {
    return DAT_00407888;
  }
  param_4 = (LPCWSTR)0x0;
  if (param_7 == 0) {
    param_7 = DAT_00407880;
  }
  iVar1 = MultiByteToWideChar(param_7,(-(uint)(param_8 != 0) & 8) + 1,param_3,(int)cbMultiByte,
                              (LPWSTR)0x0,0);
  if (iVar1 == 0) {
    return 0;
  }
  lpWideCharStr = (LPCWSTR)FUN_00402720(iVar1 * 2);
  if (lpWideCharStr == (LPCWSTR)0x0) {
    return 0;
  }
  iVar2 = MultiByteToWideChar(param_7,1,param_3,(int)cbMultiByte,lpWideCharStr,iVar1);
  if ((iVar2 != 0) &&
     (iVar2 = LCMapStringW(param_1,param_2,lpWideCharStr,iVar1,(LPWSTR)0x0,0), iVar2 != 0)) {
    if ((param_2 & 0x400) == 0) {
      param_4 = (LPCWSTR)FUN_00402720(iVar2 * 2);
      if ((param_4 == (LPCWSTR)0x0) ||
         (iVar1 = LCMapStringW(param_1,param_2,lpWideCharStr,iVar1,param_4,iVar2), iVar1 == 0))
      goto LAB_004029d8;
      if (param_6 == 0) {
        iVar2 = WideCharToMultiByte(param_7,0x220,param_4,iVar2,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0
                                   );
        iVar1 = iVar2;
      }
      else {
        iVar2 = WideCharToMultiByte(param_7,0x220,param_4,iVar2,(LPSTR)param_5,param_6,(LPCSTR)0x0,
                                    (LPBOOL)0x0);
        iVar1 = iVar2;
      }
    }
    else {
      if (param_6 == 0) goto LAB_0040293f;
      if (param_6 < iVar2) goto LAB_004029d8;
      iVar1 = LCMapStringW(param_1,param_2,lpWideCharStr,iVar1,param_5,param_6);
    }
    if (iVar1 != 0) {
LAB_0040293f:
      FUN_004026d0(lpWideCharStr);
      FUN_004026d0(param_4);
      return iVar2;
    }
  }
LAB_004029d8:
  FUN_004026d0(lpWideCharStr);
  FUN_004026d0(param_4);
  return 0;
}



int __cdecl FUN_00402a00(char *param_1,int param_2)

{
  char *pcVar1;
  int iVar2;
  
  pcVar1 = param_1;
  iVar2 = param_2;
  if (param_2 != 0) {
    do {
      iVar2 = iVar2 + -1;
      if (*pcVar1 == '\0') break;
      pcVar1 = pcVar1 + 1;
    } while (iVar2 != 0);
  }
  if (*pcVar1 == '\0') {
    return (int)pcVar1 - (int)param_1;
  }
  return param_2;
}



BOOL __cdecl
FUN_00402a30(DWORD param_1,LPCSTR param_2,int param_3,LPWORD param_4,UINT param_5,LCID param_6,
            int param_7)

{
  BOOL BVar1;
  int iVar2;
  int *lpWideCharStr;
  WORD local_2;
  
  lpWideCharStr = (int *)0x0;
  if (DAT_00407890 == 0) {
    BVar1 = GetStringTypeW(1,(LPCWSTR)&lpSrcStr_004043b8,1,&local_2);
    if (BVar1 == 0) {
      BVar1 = GetStringTypeA(0,1,(LPCSTR)&lpSrcStr_004043b4,1,&local_2);
      if (BVar1 == 0) {
        return 0;
      }
      DAT_00407890 = 2;
    }
    else {
      DAT_00407890 = 1;
    }
  }
  if (DAT_00407890 == 2) {
    if (param_6 == 0) {
      param_6 = DAT_00407870;
    }
    BVar1 = GetStringTypeA(param_6,param_1,param_2,param_3,param_4);
    return BVar1;
  }
  param_6 = DAT_00407890;
  if (DAT_00407890 == 1) {
    param_6 = 0;
    if (param_5 == 0) {
      param_5 = DAT_00407880;
    }
    iVar2 = MultiByteToWideChar(param_5,(-(uint)(param_7 != 0) & 8) + 1,param_2,param_3,(LPWSTR)0x0,
                                0);
    if (iVar2 != 0) {
      lpWideCharStr = FUN_00403780(2,iVar2);
      if (lpWideCharStr != (int *)0x0) {
        iVar2 = MultiByteToWideChar(param_5,1,param_2,param_3,(LPWSTR)lpWideCharStr,iVar2);
        if (iVar2 != 0) {
          BVar1 = GetStringTypeW(param_1,(LPCWSTR)lpWideCharStr,iVar2,param_4);
          FUN_004026d0(lpWideCharStr);
          return BVar1;
        }
      }
    }
    FUN_004026d0(lpWideCharStr);
  }
  return param_6;
}



undefined4 * FUN_00402b70(void)

{
  bool bVar1;
  undefined4 *lpAddress;
  LPVOID pvVar2;
  int iVar3;
  int *piVar4;
  undefined4 *lpMem;
  undefined4 *puVar5;
  
  if (DAT_004054b0 == -1) {
    lpMem = &DAT_004054a0;
  }
  else {
    lpMem = (undefined4 *)HeapAlloc(DAT_004078ac,0,0x2020);
    if (lpMem == (undefined4 *)0x0) {
      return (undefined4 *)0x0;
    }
  }
  lpAddress = (undefined4 *)VirtualAlloc((LPVOID)0x0,0x400000,0x2000,4);
  if (lpAddress != (undefined4 *)0x0) {
    pvVar2 = VirtualAlloc(lpAddress,0x10000,0x1000,4);
    if (pvVar2 != (LPVOID)0x0) {
      if ((undefined4 **)lpMem == &DAT_004054a0) {
        if (DAT_004054a0 == (undefined4 *)0x0) {
          DAT_004054a0 = &DAT_004054a0;
        }
        if (DAT_004054a4 == (undefined4 *)0x0) {
          DAT_004054a4 = &DAT_004054a0;
        }
      }
      else {
        *lpMem = &DAT_004054a0;
        lpMem[1] = DAT_004054a4;
        DAT_004054a4 = lpMem;
        *(undefined4 **)lpMem[1] = lpMem;
      }
      lpMem[5] = lpAddress + 0x100000;
      lpMem[4] = lpAddress;
      lpMem[2] = lpMem + 6;
      lpMem[3] = lpMem + 0x26;
      iVar3 = 0;
      piVar4 = lpMem + 6;
      do {
        bVar1 = 0xf < iVar3;
        iVar3 = iVar3 + 1;
        *piVar4 = (bVar1 - 1 & 0xf1) - 1;
        piVar4[1] = 0xf1;
        piVar4 = piVar4 + 2;
      } while (iVar3 < 0x400);
      puVar5 = lpAddress;
      for (iVar3 = 0x4000; iVar3 != 0; iVar3 = iVar3 + -1) {
        *puVar5 = 0;
        puVar5 = puVar5 + 1;
      }
      if (lpAddress < (undefined4 *)(lpMem[4] + 0x10000)) {
        do {
          lpAddress[1] = 0xf0;
          *lpAddress = lpAddress + 2;
          *(undefined *)(lpAddress + 0x3e) = 0xff;
          lpAddress = lpAddress + 0x400;
        } while (lpAddress < (undefined4 *)(lpMem[4] + 0x10000));
      }
      return lpMem;
    }
    VirtualFree(lpAddress,0,0x8000);
  }
  if ((undefined4 **)lpMem != &DAT_004054a0) {
    HeapFree(DAT_004078ac,0,lpMem);
  }
  return (undefined4 *)0x0;
}



void __cdecl FUN_00402ce0(int *param_1)

{
  VirtualFree((LPVOID)param_1[4],0,0x8000);
  if (DAT_004074c0 == param_1) {
    DAT_004074c0 = (int *)param_1[1];
  }
  if (param_1 != &DAT_004054a0) {
    *(int *)param_1[1] = *param_1;
    *(int *)(*param_1 + 4) = param_1[1];
    HeapFree(DAT_004078ac,0,param_1);
    return;
  }
  DAT_004054b0 = 0xffffffff;
  return;
}



void __cdecl FUN_00402d40(int param_1)

{
  BOOL BVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int *piVar6;
  
  piVar6 = DAT_004054a4;
  do {
    piVar5 = piVar6;
    if (piVar6[4] != -1) {
      iVar4 = 0;
      piVar5 = piVar6 + 0x804;
      iVar3 = 0x3ff000;
      do {
        if (*piVar5 == 0xf0) {
          BVar1 = VirtualFree((LPVOID)(piVar6[4] + iVar3),0x1000,0x4000);
          if (BVar1 != 0) {
            *piVar5 = -1;
            DAT_00407894 = DAT_00407894 + -1;
            if (((int *)piVar6[3] == (int *)0x0) || (piVar5 < (int *)piVar6[3])) {
              piVar6[3] = (int)piVar5;
            }
            iVar4 = iVar4 + 1;
            param_1 = param_1 + -1;
            if (param_1 == 0) break;
          }
        }
        iVar3 = iVar3 + -0x1000;
        piVar5 = piVar5 + -2;
      } while (-1 < iVar3);
      piVar5 = (int *)piVar6[1];
      if ((iVar4 != 0) && (piVar6[6] == -1)) {
        iVar3 = 1;
        piVar2 = piVar6 + 8;
        do {
          if (*piVar2 != -1) break;
          iVar3 = iVar3 + 1;
          piVar2 = piVar2 + 2;
        } while (iVar3 < 0x400);
        if (iVar3 == 0x400) {
          FUN_00402ce0(piVar6);
        }
      }
    }
    if ((piVar5 == DAT_004054a4) || (piVar6 = piVar5, param_1 < 1)) {
      return;
    }
  } while( true );
}



int __cdecl FUN_00402e10(uint param_1,undefined4 *param_2,uint *param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  
  puVar1 = &DAT_004054a0;
  while ((param_1 <= (uint)puVar1[4] || ((uint)puVar1[5] <= param_1))) {
    puVar1 = (undefined4 *)*puVar1;
    if (puVar1 == &DAT_004054a0) {
      return 0;
    }
  }
  if ((param_1 & 0xf) != 0) {
    return 0;
  }
  if ((param_1 & 0xfff) < 0x100) {
    return 0;
  }
  *param_2 = puVar1;
  uVar2 = param_1 & 0xfffff000;
  *param_3 = uVar2;
  return ((int)((param_1 - uVar2) + -0x100) >> 4) + 8 + uVar2;
}



void __cdecl FUN_00402e70(int param_1,int param_2,byte *param_3)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = param_2 - *(int *)(param_1 + 0x10) >> 0xc;
  piVar1 = (int *)(param_1 + 0x18 + iVar2 * 8);
  *piVar1 = *(int *)(param_1 + 0x18 + iVar2 * 8) + (uint)*param_3;
  *param_3 = 0;
  piVar1[1] = 0xf1;
  if ((*piVar1 == 0xf0) && (DAT_00407894 = DAT_00407894 + 1, DAT_00407894 == 0x20)) {
    FUN_00402d40(0x10);
  }
  return;
}



int * __cdecl FUN_00402ed0(int *param_1)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  int *piVar4;
  undefined4 *puVar5;
  int **ppiVar6;
  int iVar7;
  int **ppiVar8;
  int **ppiVar9;
  int *lpAddress;
  bool bVar10;
  int *local_4;
  
  local_4 = DAT_004074c0;
  do {
    if (local_4[4] != -1) {
      ppiVar8 = (int **)local_4[2];
      ppiVar6 = (int **)(((int)ppiVar8 + (-0x18 - (int)local_4) >> 3) * 0x1000 + local_4[4]);
      for (; ppiVar8 < local_4 + 0x806; ppiVar8 = ppiVar8 + 2) {
        if (((int)param_1 <= (int)*ppiVar8) && (param_1 < ppiVar8[1])) {
          piVar2 = (int *)FUN_00403110(ppiVar6,*ppiVar8,param_1);
          if (piVar2 != (int *)0x0) {
            DAT_004074c0 = local_4;
            *ppiVar8 = (int *)((int)*ppiVar8 - (int)param_1);
            local_4[2] = (int)ppiVar8;
            return piVar2;
          }
          ppiVar8[1] = param_1;
        }
        ppiVar6 = ppiVar6 + 0x400;
      }
      ppiVar6 = (int **)local_4[2];
      ppiVar9 = (int **)local_4[4];
      for (ppiVar8 = (int **)(local_4 + 6); ppiVar8 < ppiVar6; ppiVar8 = ppiVar8 + 2) {
        if (((int)param_1 <= (int)*ppiVar8) && (param_1 < ppiVar8[1])) {
          piVar2 = (int *)FUN_00403110(ppiVar9,*ppiVar8,param_1);
          if (piVar2 != (int *)0x0) {
            DAT_004074c0 = local_4;
            *ppiVar8 = (int *)((int)*ppiVar8 - (int)param_1);
            local_4[2] = (int)ppiVar8;
            return piVar2;
          }
          ppiVar8[1] = param_1;
        }
        ppiVar9 = ppiVar9 + 0x400;
      }
    }
    local_4 = (int *)*local_4;
  } while (local_4 != DAT_004074c0);
  puVar5 = &DAT_004054a0;
  while ((puVar5[4] == -1 || (puVar5[3] == 0))) {
    puVar5 = (undefined4 *)*puVar5;
    if (puVar5 == &DAT_004054a0) {
      puVar5 = FUN_00402b70();
      if (puVar5 == (undefined4 *)0x0) {
        return (int *)0x0;
      }
      piVar2 = (int *)puVar5[4];
      *(char *)(piVar2 + 2) = (char)param_1;
      DAT_004074c0 = puVar5;
      *piVar2 = (int)(piVar2 + 2) + (int)param_1;
      piVar2[1] = 0xf0 - (int)param_1;
      puVar5[6] = puVar5[6] - ((uint)param_1 & 0xff);
      return piVar2 + 0x40;
    }
  }
  piVar2 = (int *)puVar5[3];
  iVar1 = *piVar2;
  lpAddress = (int *)(((int)piVar2 + (-0x18 - (int)puVar5) >> 3) * 0x1000 + puVar5[4]);
  piVar3 = piVar2;
  for (iVar7 = 0; (iVar1 == -1 && (iVar7 < 0x10)); iVar7 = iVar7 + 1) {
    iVar1 = piVar3[2];
    piVar3 = piVar3 + 2;
  }
  piVar3 = (int *)VirtualAlloc(lpAddress,iVar7 << 0xc,0x1000,4);
  if (piVar3 != lpAddress) {
    return (int *)0x0;
  }
  piVar3 = piVar2;
  if (0 < iVar7) {
    piVar4 = lpAddress + 1;
    do {
      *piVar4 = 0xf0;
      piVar4[-1] = (int)(piVar4 + 1);
      *(undefined *)(piVar4 + 0x3d) = 0xff;
      *piVar3 = 0xf0;
      piVar3[1] = 0xf1;
      piVar4 = piVar4 + 0x400;
      piVar3 = piVar3 + 2;
      iVar7 = iVar7 + -1;
    } while (iVar7 != 0);
  }
  piVar4 = puVar5 + 0x806;
  bVar10 = piVar3 < piVar4;
  if (bVar10) {
    do {
      if (*piVar3 == -1) break;
      piVar3 = piVar3 + 2;
    } while (piVar3 < piVar4);
    bVar10 = piVar3 < piVar4;
  }
  DAT_004074c0 = puVar5;
  puVar5[3] = -(uint)bVar10 & (uint)piVar3;
  *(char *)(lpAddress + 2) = (char)param_1;
  puVar5[2] = piVar2;
  *piVar2 = *piVar2 - (int)param_1;
  lpAddress[1] = lpAddress[1] - (int)param_1;
  *lpAddress = (int)(lpAddress + 2) + (int)param_1;
  return lpAddress + 0x40;
}



int __cdecl FUN_00403110(int **param_1,int *param_2,int *param_3)

{
  byte bVar1;
  int **ppiVar2;
  int **ppiVar3;
  int **ppiVar4;
  int *piVar5;
  int **ppiVar6;
  
  ppiVar2 = (int **)*param_1;
  if (param_3 <= param_1[1]) {
    *(byte *)ppiVar2 = (byte)param_3;
    if ((int **)((int)ppiVar2 + (int)param_3) < param_1 + 0x3e) {
      *param_1 = (int *)((int)*param_1 + (int)param_3);
      param_1[1] = (int *)((int)param_1[1] - (int)param_3);
    }
    else {
      param_1[1] = (int *)0x0;
      *param_1 = (int *)(param_1 + 2);
    }
    return (int)(ppiVar2 + 2) * 0x10 + (int)param_1 * -0xf;
  }
  ppiVar3 = (int **)((int)param_1[1] + (int)ppiVar2);
  ppiVar6 = ppiVar2;
  if (*(byte *)ppiVar3 != 0) {
    ppiVar6 = ppiVar3;
  }
  if ((int **)((int)ppiVar6 + (int)param_3) < param_1 + 0x3e) {
    do {
      if (*(byte *)ppiVar6 == 0) {
        ppiVar3 = (int **)((int)ppiVar6 + 1);
        piVar5 = (int *)0x1;
        bVar1 = *(byte *)((int)ppiVar6 + 1);
        while (bVar1 == 0) {
          ppiVar3 = (int **)((int)ppiVar3 + 1);
          piVar5 = (int *)((int)piVar5 + 1);
          bVar1 = *(byte *)ppiVar3;
        }
        if (param_3 <= piVar5) {
          if (param_1 + 0x3e <= (int **)((int)ppiVar6 + (int)param_3)) {
            *param_1 = (int *)(param_1 + 2);
            goto LAB_0040325f;
          }
          *param_1 = (int *)(int **)((int)ppiVar6 + (int)param_3);
          param_1[1] = (int *)((int)piVar5 - (int)param_3);
          goto LAB_00403266;
        }
        if (ppiVar6 == ppiVar2) {
          param_1[1] = piVar5;
        }
        else {
          param_2 = (int *)((int)param_2 - (int)piVar5);
          if (param_2 < param_3) {
            return 0;
          }
        }
      }
      else {
        ppiVar3 = (int **)((int)ppiVar6 + (uint)*(byte *)ppiVar6);
      }
      ppiVar6 = ppiVar3;
    } while ((int **)((int)ppiVar3 + (int)param_3) < param_1 + 0x3e);
  }
  ppiVar3 = param_1 + 2;
  ppiVar6 = ppiVar3;
  if (ppiVar3 < ppiVar2) {
    while ((int **)((int)ppiVar6 + (int)param_3) < param_1 + 0x3e) {
      if (*(byte *)ppiVar6 == 0) {
        ppiVar4 = (int **)((int)ppiVar6 + 1);
        piVar5 = (int *)0x1;
        bVar1 = *(byte *)((int)ppiVar6 + 1);
        while (bVar1 == 0) {
          ppiVar4 = (int **)((int)ppiVar4 + 1);
          piVar5 = (int *)((int)piVar5 + 1);
          bVar1 = *(byte *)ppiVar4;
        }
        if (param_3 <= piVar5) {
          if ((int **)((int)ppiVar6 + (int)param_3) < param_1 + 0x3e) {
            *param_1 = (int *)(int **)((int)ppiVar6 + (int)param_3);
            param_1[1] = (int *)((int)piVar5 - (int)param_3);
          }
          else {
            *param_1 = (int *)ppiVar3;
LAB_0040325f:
            param_1[1] = (int *)0x0;
          }
LAB_00403266:
          *(byte *)ppiVar6 = (byte)param_3;
          return (int)(ppiVar6 + 2) * 0x10 + (int)param_1 * -0xf;
        }
        param_2 = (int *)((int)param_2 - (int)piVar5);
        if (param_2 < param_3) {
          return 0;
        }
      }
      else {
        ppiVar4 = (int **)((int)ppiVar6 + (uint)*(byte *)ppiVar6);
      }
      ppiVar6 = ppiVar4;
      if (ppiVar2 <= ppiVar4) {
        return 0;
      }
    }
  }
  return 0;
}



int __cdecl FUN_00403290(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  HMODULE hModule;
  int iVar1;
  
  iVar1 = 0;
  if (DAT_00407898 != (FARPROC)0x0) {
LAB_004032e0:
    if (DAT_0040789c != (FARPROC)0x0) {
      iVar1 = (*DAT_0040789c)();
    }
    if ((iVar1 != 0) && (DAT_004078a0 != (FARPROC)0x0)) {
      iVar1 = (*DAT_004078a0)(iVar1);
    }
    iVar1 = (*DAT_00407898)(iVar1,param_1,param_2,param_3);
    return iVar1;
  }
  hModule = LoadLibraryA("user32.dll");
  if (hModule != (HMODULE)0x0) {
    DAT_00407898 = GetProcAddress(hModule,"MessageBoxA");
    if (DAT_00407898 != (FARPROC)0x0) {
      DAT_0040789c = GetProcAddress(hModule,"GetActiveWindow");
      DAT_004078a0 = GetProcAddress(hModule,"GetLastActivePopup");
      goto LAB_004032e0;
    }
  }
  return 0;
}



// Library Function - Single Match
//  _strncpy
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

char * __cdecl _strncpy(char *_Dest,char *_Source,size_t _Count)

{
  uint uVar1;
  uint uVar2;
  char cVar3;
  uint uVar4;
  uint *puVar5;
  
  if (_Count == 0) {
    return _Dest;
  }
  puVar5 = (uint *)_Dest;
  if (((uint)_Source & 3) != 0) {
    while( true ) {
      cVar3 = *_Source;
      _Source = (char *)((int)_Source + 1);
      *(char *)puVar5 = cVar3;
      puVar5 = (uint *)((int)puVar5 + 1);
      _Count = _Count - 1;
      if (_Count == 0) {
        return _Dest;
      }
      if (cVar3 == '\0') break;
      if (((uint)_Source & 3) == 0) {
        uVar4 = _Count >> 2;
        goto joined_r0x0040335e;
      }
    }
    do {
      if (((uint)puVar5 & 3) == 0) {
        uVar4 = _Count >> 2;
        cVar3 = '\0';
        if (uVar4 == 0) goto LAB_0040339b;
        goto LAB_00403409;
      }
      *(undefined *)puVar5 = 0;
      puVar5 = (uint *)((int)puVar5 + 1);
      _Count = _Count - 1;
    } while (_Count != 0);
    return _Dest;
  }
  uVar4 = _Count >> 2;
  if (uVar4 != 0) {
    do {
      uVar1 = *(uint *)_Source;
      uVar2 = *(uint *)_Source;
      _Source = (char *)((int)_Source + 4);
      if (((uVar1 ^ 0xffffffff ^ uVar1 + 0x7efefeff) & 0x81010100) != 0) {
        if ((char)uVar2 == '\0') {
          *puVar5 = 0;
joined_r0x00403405:
          while( true ) {
            uVar4 = uVar4 - 1;
            puVar5 = puVar5 + 1;
            if (uVar4 == 0) break;
LAB_00403409:
            *puVar5 = 0;
          }
          cVar3 = '\0';
          _Count = _Count & 3;
          if (_Count != 0) goto LAB_0040339b;
          return _Dest;
        }
        if ((char)(uVar2 >> 8) == '\0') {
          *puVar5 = uVar2 & 0xff;
          goto joined_r0x00403405;
        }
        if ((uVar2 & 0xff0000) == 0) {
          *puVar5 = uVar2 & 0xffff;
          goto joined_r0x00403405;
        }
        if ((uVar2 & 0xff000000) == 0) {
          *puVar5 = uVar2;
          goto joined_r0x00403405;
        }
      }
      *puVar5 = uVar2;
      puVar5 = puVar5 + 1;
      uVar4 = uVar4 - 1;
joined_r0x0040335e:
    } while (uVar4 != 0);
    _Count = _Count & 3;
    if (_Count == 0) {
      return _Dest;
    }
  }
  do {
    cVar3 = *_Source;
    _Source = (char *)((int)_Source + 1);
    *(char *)puVar5 = cVar3;
    puVar5 = (uint *)((int)puVar5 + 1);
    if (cVar3 == '\0') {
      while (_Count = _Count - 1, _Count != 0) {
LAB_0040339b:
        *(char *)puVar5 = cVar3;
        puVar5 = (uint *)((int)puVar5 + 1);
      }
      return _Dest;
    }
    _Count = _Count - 1;
  } while (_Count != 0);
  return _Dest;
}



undefined4 __cdecl FUN_00403420(undefined4 param_1)

{
  int iVar1;
  
  if (DAT_004078a8 != (code *)0x0) {
    iVar1 = (*DAT_004078a8)(param_1);
    if (iVar1 != 0) {
      return 1;
    }
  }
  return 0;
}



undefined4 * __cdecl FUN_00403440(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  if ((param_2 < param_1) && (param_1 < (undefined4 *)(param_3 + (int)param_2))) {
    puVar3 = (undefined4 *)((param_3 - 4) + (int)param_2);
    puVar4 = (undefined4 *)((param_3 - 4) + (int)param_1);
    if (((uint)puVar4 & 3) == 0) {
      uVar1 = param_3 >> 2;
      uVar2 = param_3 & 3;
      if (7 < uVar1) {
        for (; uVar1 != 0; uVar1 = uVar1 - 1) {
          *puVar4 = *puVar3;
          puVar3 = puVar3 + -1;
          puVar4 = puVar4 + -1;
        }
        switch(uVar2) {
        case 0:
          return param_1;
        case 2:
          goto switchD_004035f7_caseD_2;
        case 3:
          goto switchD_004035f7_caseD_3;
        }
        goto switchD_004035f7_caseD_1;
      }
    }
    else {
      switch(param_3) {
      case 0:
        goto switchD_004035f7_caseD_0;
      case 1:
        goto switchD_004035f7_caseD_1;
      case 2:
        goto switchD_004035f7_caseD_2;
      case 3:
        goto switchD_004035f7_caseD_3;
      default:
        uVar1 = param_3 - ((uint)puVar4 & 3);
        switch((uint)puVar4 & 3) {
        case 1:
          uVar2 = uVar1 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
          puVar3 = (undefined4 *)((int)puVar3 + -1);
          uVar1 = uVar1 >> 2;
          puVar4 = (undefined4 *)((int)puVar4 - 1);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_004035f7_caseD_2;
            case 3:
              goto switchD_004035f7_caseD_3;
            }
            goto switchD_004035f7_caseD_1;
          }
          break;
        case 2:
          uVar2 = uVar1 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
          uVar1 = uVar1 >> 2;
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
          puVar3 = (undefined4 *)((int)puVar3 + -2);
          puVar4 = (undefined4 *)((int)puVar4 - 2);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_004035f7_caseD_2;
            case 3:
              goto switchD_004035f7_caseD_3;
            }
            goto switchD_004035f7_caseD_1;
          }
          break;
        case 3:
          uVar2 = uVar1 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
          uVar1 = uVar1 >> 2;
          *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar3 + 1);
          puVar3 = (undefined4 *)((int)puVar3 + -3);
          puVar4 = (undefined4 *)((int)puVar4 - 3);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_004035f7_caseD_2;
            case 3:
              goto switchD_004035f7_caseD_3;
            }
            goto switchD_004035f7_caseD_1;
          }
        }
      }
    }
    switch(uVar1) {
    case 7:
      puVar4[7 - uVar1] = puVar3[7 - uVar1];
    case 6:
      puVar4[6 - uVar1] = puVar3[6 - uVar1];
    case 5:
      puVar4[5 - uVar1] = puVar3[5 - uVar1];
    case 4:
      puVar4[4 - uVar1] = puVar3[4 - uVar1];
    case 3:
      puVar4[3 - uVar1] = puVar3[3 - uVar1];
    case 2:
      puVar4[2 - uVar1] = puVar3[2 - uVar1];
    case 1:
      puVar4[1 - uVar1] = puVar3[1 - uVar1];
      puVar3 = puVar3 + -uVar1;
      puVar4 = puVar4 + -uVar1;
    }
    switch(uVar2) {
    case 1:
switchD_004035f7_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      return param_1;
    case 2:
switchD_004035f7_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
      return param_1;
    case 3:
switchD_004035f7_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar3 + 1);
      return param_1;
    }
switchD_004035f7_caseD_0:
    return param_1;
  }
  puVar3 = param_1;
  if (((uint)param_1 & 3) == 0) {
    uVar1 = param_3 >> 2;
    uVar2 = param_3 & 3;
    if (7 < uVar1) {
      for (; uVar1 != 0; uVar1 = uVar1 - 1) {
        *puVar3 = *param_2;
        param_2 = param_2 + 1;
        puVar3 = puVar3 + 1;
      }
      switch(uVar2) {
      case 0:
        return param_1;
      case 2:
        goto switchD_00403475_caseD_2;
      case 3:
        goto switchD_00403475_caseD_3;
      }
      goto switchD_00403475_caseD_1;
    }
  }
  else {
    switch(param_3) {
    case 0:
      goto switchD_00403475_caseD_0;
    case 1:
      goto switchD_00403475_caseD_1;
    case 2:
      goto switchD_00403475_caseD_2;
    case 3:
      goto switchD_00403475_caseD_3;
    default:
      uVar1 = (param_3 - 4) + ((uint)param_1 & 3);
      switch((uint)param_1 & 3) {
      case 1:
        uVar2 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        uVar1 = uVar1 >> 2;
        *(undefined *)((int)param_1 + 2) = *(undefined *)((int)param_2 + 2);
        param_2 = (undefined4 *)((int)param_2 + 3);
        puVar3 = (undefined4 *)((int)param_1 + 3);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_00403475_caseD_2;
          case 3:
            goto switchD_00403475_caseD_3;
          }
          goto switchD_00403475_caseD_1;
        }
        break;
      case 2:
        uVar2 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        uVar1 = uVar1 >> 2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        param_2 = (undefined4 *)((int)param_2 + 2);
        puVar3 = (undefined4 *)((int)param_1 + 2);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_00403475_caseD_2;
          case 3:
            goto switchD_00403475_caseD_3;
          }
          goto switchD_00403475_caseD_1;
        }
        break;
      case 3:
        uVar2 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        param_2 = (undefined4 *)((int)param_2 + 1);
        uVar1 = uVar1 >> 2;
        puVar3 = (undefined4 *)((int)param_1 + 1);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_00403475_caseD_2;
          case 3:
            goto switchD_00403475_caseD_3;
          }
          goto switchD_00403475_caseD_1;
        }
      }
    }
  }
                    // WARNING: Could not find normalized switch variable to match jumptable
  switch(uVar1) {
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 7] = param_2[uVar1 - 7];
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 6] = param_2[uVar1 - 6];
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 5] = param_2[uVar1 - 5];
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 4] = param_2[uVar1 - 4];
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 3] = param_2[uVar1 - 3];
  case 8:
  case 9:
  case 10:
  case 0xb:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 2] = param_2[uVar1 - 2];
  case 4:
  case 5:
  case 6:
  case 7:
    puVar3[uVar1 - 1] = param_2[uVar1 - 1];
    param_2 = param_2 + uVar1;
    puVar3 = puVar3 + uVar1;
  }
  switch(uVar2) {
  case 1:
switchD_00403475_caseD_1:
    *(undefined *)puVar3 = *(undefined *)param_2;
    return param_1;
  case 2:
switchD_00403475_caseD_2:
    *(undefined *)puVar3 = *(undefined *)param_2;
    *(undefined *)((int)puVar3 + 1) = *(undefined *)((int)param_2 + 1);
    return param_1;
  case 3:
switchD_00403475_caseD_3:
    *(undefined *)puVar3 = *(undefined *)param_2;
    *(undefined *)((int)puVar3 + 1) = *(undefined *)((int)param_2 + 1);
    *(undefined *)((int)puVar3 + 2) = *(undefined *)((int)param_2 + 2);
    return param_1;
  }
switchD_00403475_caseD_0:
  return param_1;
}



int * __cdecl FUN_00403780(int param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  uint dwBytes;
  int *piVar4;
  
  dwBytes = param_2 * param_1;
  if (dwBytes < 0xffffffe1) {
    if (dwBytes == 0) {
      dwBytes = 0x10;
    }
    else {
      dwBytes = dwBytes + 0xf & 0xfffffff0;
    }
  }
  do {
    piVar3 = (int *)0x0;
    if (dwBytes < 0xffffffe1) {
      if (DAT_004074c4 < dwBytes) {
LAB_004037e0:
        if (piVar3 != (int *)0x0) {
          return piVar3;
        }
      }
      else {
        piVar3 = FUN_00402ed0((int *)(dwBytes >> 4));
        if (piVar3 != (int *)0x0) {
          piVar4 = piVar3;
          for (uVar2 = dwBytes >> 2; uVar2 != 0; uVar2 = uVar2 - 1) {
            *piVar4 = 0;
            piVar4 = piVar4 + 1;
          }
          for (uVar2 = dwBytes & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
            *(undefined *)piVar4 = 0;
            piVar4 = (int *)((int)piVar4 + 1);
          }
          goto LAB_004037e0;
        }
      }
      piVar3 = (int *)HeapAlloc(DAT_004078ac,8,dwBytes);
    }
    if ((piVar3 != (int *)0x0) || (DAT_004078a4 == 0)) {
      return piVar3;
    }
    iVar1 = FUN_00403420(dwBytes);
    if (iVar1 == 0) {
      return (int *)0x0;
    }
  } while( true );
}



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x00403820. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}


