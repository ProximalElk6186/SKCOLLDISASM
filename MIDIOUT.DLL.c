typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined5;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef short    wchar_t;
typedef unsigned short    word;
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

typedef unsigned short    wchar16;
typedef struct _cpinfo _cpinfo, *P_cpinfo;

typedef uint UINT;

typedef uchar BYTE;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo *LPCPINFO;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef ulong DWORD;

typedef char CHAR;

typedef CHAR *LPSTR;

typedef ushort WORD;

typedef BYTE *LPBYTE;

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

typedef struct _PROCESS_HEAP_ENTRY _PROCESS_HEAP_ENTRY, *P_PROCESS_HEAP_ENTRY;

typedef void *PVOID;

typedef union _union_548 _union_548, *P_union_548;

typedef struct _struct_549 _struct_549, *P_struct_549;

typedef struct _struct_550 _struct_550, *P_struct_550;

typedef void *LPVOID;

struct _struct_550 {
    DWORD dwCommittedSize;
    DWORD dwUnCommittedSize;
    LPVOID lpFirstBlock;
    LPVOID lpLastBlock;
};

struct _struct_549 {
    HANDLE hMem;
    DWORD dwReserved[3];
};

union _union_548 {
    struct _struct_549 Block;
    struct _struct_550 Region;
};

struct _PROCESS_HEAP_ENTRY {
    PVOID lpData;
    DWORD cbData;
    BYTE cbOverhead;
    BYTE iRegionIndex;
    WORD wFlags;
    union _union_548 u;
};

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulong ULONG_PTR;

typedef union _union_518 _union_518, *P_union_518;

typedef struct _struct_519 _struct_519, *P_struct_519;

struct _struct_519 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_518 {
    struct _struct_519 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_518 u;
    HANDLE hEvent;
};

typedef struct _PROCESS_HEAP_ENTRY *LPPROCESS_HEAP_ENTRY;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG *PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION *CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (*PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

typedef CONTEXT *PCONTEXT;

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

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef wchar_t WCHAR;

typedef CHAR *LPCSTR;

typedef LONG *PLONG;

typedef CHAR *LPCH;

typedef WCHAR *LPWSTR;

typedef WCHAR *LPWCH;

typedef WCHAR *LPCWSTR;

typedef DWORD LCID;

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

typedef ULONG_PTR DWORD_PTR;

typedef ULONG_PTR SIZE_T;

typedef uint UINT_PTR;

typedef long LONG_PTR;

typedef int (*FARPROC)(void);

typedef UINT_PTR WPARAM;

typedef WORD *LPWORD;

typedef DWORD *LPDWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef HANDLE HGLOBAL;

typedef LONG_PTR LPARAM;

typedef int BOOL;

typedef BOOL *LPBOOL;

typedef struct HINSTANCE__ *HINSTANCE;

typedef void *LPCVOID;

typedef struct HRSRC__ HRSRC__, *PHRSRC__;

typedef struct HRSRC__ *HRSRC;

struct HRSRC__ {
    int unused;
};

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

typedef HINSTANCE HMODULE;

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

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_6 IMAGE_RESOURCE_DIR_STRING_U_6, *PIMAGE_RESOURCE_DIR_STRING_U_6;

struct IMAGE_RESOURCE_DIR_STRING_U_6 {
    word Length;
    wchar16 NameString[3];
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

typedef struct IMAGE_DIRECTORY_ENTRY_EXPORT IMAGE_DIRECTORY_ENTRY_EXPORT, *PIMAGE_DIRECTORY_ENTRY_EXPORT;

struct IMAGE_DIRECTORY_ENTRY_EXPORT {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Name;
    dword Base;
    dword NumberOfFunctions;
    dword NumberOfNames;
    dword AddressOfFunctions;
    dword AddressOfNames;
    dword AddressOfNameOrdinals;
};

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char *_ptr;
    int _cnt;
    char *_base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char *_tmpfname;
};

typedef struct _iobuf FILE;

typedef BOOL (*PHANDLER_ROUTINE)(DWORD);

typedef char *va_list;

typedef uint uintptr_t;

typedef void (TIMECALLBACK)(UINT, UINT, DWORD_PTR, DWORD_PTR, DWORD_PTR);

typedef TIMECALLBACK *LPTIMECALLBACK;

typedef struct tagMIDIOUTCAPSA tagMIDIOUTCAPSA, *PtagMIDIOUTCAPSA;

typedef UINT MMVERSION;

struct tagMIDIOUTCAPSA {
    WORD wMid;
    WORD wPid;
    MMVERSION vDriverVersion;
    CHAR szPname[32];
    WORD wTechnology;
    WORD wVoices;
    WORD wNotes;
    WORD wChannelMask;
    DWORD dwSupport;
};

typedef struct HMIDIOUT__ HMIDIOUT__, *PHMIDIOUT__;

typedef struct HMIDIOUT__ *HMIDIOUT;

struct HMIDIOUT__ {
    int unused;
};

typedef UINT MMRESULT;

typedef struct midihdr_tag midihdr_tag, *Pmidihdr_tag;

struct midihdr_tag {
    LPSTR lpData;
    DWORD dwBufferLength;
    DWORD dwBytesRecorded;
    DWORD_PTR dwUser;
    DWORD dwFlags;
    struct midihdr_tag *lpNext;
    DWORD_PTR reserved;
    DWORD dwOffset;
    DWORD_PTR dwReserved[8];
};

typedef struct timecaps_tag timecaps_tag, *Ptimecaps_tag;

struct timecaps_tag {
    UINT wPeriodMin;
    UINT wPeriodMax;
};

typedef struct midihdr_tag *LPMIDIHDR;

typedef struct timecaps_tag *LPTIMECAPS;

typedef struct tagMIDIOUTCAPSA *LPMIDIOUTCAPSA;

typedef HMIDIOUT *LPHMIDIOUT;

typedef struct _tiddata _tiddata, *P_tiddata;

typedef struct _tiddata *_ptiddata;

typedef struct threadmbcinfostruct threadmbcinfostruct, *Pthreadmbcinfostruct;

typedef struct threadmbcinfostruct *pthreadmbcinfo;

typedef struct threadlocaleinfostruct threadlocaleinfostruct, *Pthreadlocaleinfostruct;

typedef struct threadlocaleinfostruct *pthreadlocinfo;

typedef struct setloc_struct setloc_struct, *Psetloc_struct;

typedef struct setloc_struct _setloc_struct;

typedef struct localerefcount localerefcount, *Plocalerefcount;

typedef struct localerefcount locrefcount;

typedef struct lconv lconv, *Plconv;

typedef struct __lc_time_data __lc_time_data, *P__lc_time_data;

typedef struct _is_ctype_compatible _is_ctype_compatible, *P_is_ctype_compatible;

struct lconv {
    char *decimal_point;
    char *thousands_sep;
    char *grouping;
    char *int_curr_symbol;
    char *currency_symbol;
    char *mon_decimal_point;
    char *mon_thousands_sep;
    char *mon_grouping;
    char *positive_sign;
    char *negative_sign;
    char int_frac_digits;
    char frac_digits;
    char p_cs_precedes;
    char p_sep_by_space;
    char n_cs_precedes;
    char n_sep_by_space;
    char p_sign_posn;
    char n_sign_posn;
    wchar_t *_W_decimal_point;
    wchar_t *_W_thousands_sep;
    wchar_t *_W_int_curr_symbol;
    wchar_t *_W_currency_symbol;
    wchar_t *_W_mon_decimal_point;
    wchar_t *_W_mon_thousands_sep;
    wchar_t *_W_positive_sign;
    wchar_t *_W_negative_sign;
};

struct _is_ctype_compatible {
    ulong id;
    int is_clike;
};

struct setloc_struct {
    wchar_t *pchLanguage;
    wchar_t *pchCountry;
    int iLocState;
    int iPrimaryLen;
    BOOL bAbbrevLanguage;
    BOOL bAbbrevCountry;
    UINT _cachecp;
    wchar_t _cachein[131];
    wchar_t _cacheout[131];
    struct _is_ctype_compatible _Loc_c[5];
    wchar_t _cacheLocaleName[85];
};

struct threadmbcinfostruct {
    int refcount;
    int mbcodepage;
    int ismbcodepage;
    ushort mbulinfo[6];
    uchar mbctype[257];
    uchar mbcasemap[256];
    wchar_t *mblocalename;
};

struct localerefcount {
    char *locale;
    wchar_t *wlocale;
    int *refcount;
    int *wrefcount;
};

struct threadlocaleinfostruct {
    int refcount;
    uint lc_codepage;
    uint lc_collate_cp;
    uint lc_time_cp;
    locrefcount lc_category[6];
    int lc_clike;
    int mb_cur_max;
    int *lconv_intl_refcount;
    int *lconv_num_refcount;
    int *lconv_mon_refcount;
    struct lconv *lconv;
    int *ctype1_refcount;
    ushort *ctype1;
    ushort *pctype;
    uchar *pclmap;
    uchar *pcumap;
    struct __lc_time_data *lc_time_curr;
    wchar_t *locale_name[6];
};

struct _tiddata {
    ulong _tid;
    uintptr_t _thandle;
    int _terrno;
    ulong _tdoserrno;
    uint _fpds;
    ulong _holdrand;
    char *_token;
    wchar_t *_wtoken;
    uchar *_mtoken;
    char *_errmsg;
    wchar_t *_werrmsg;
    char *_namebuf0;
    wchar_t *_wnamebuf0;
    char *_namebuf1;
    wchar_t *_wnamebuf1;
    char *_asctimebuf;
    wchar_t *_wasctimebuf;
    void *_gmtimebuf;
    char *_cvtbuf;
    uchar _con_ch_buf[5];
    ushort _ch_buf_used;
    void *_initaddr;
    void *_initarg;
    void *_pxcptacttab;
    void *_tpxcptinfoptrs;
    int _tfpecode;
    pthreadmbcinfo ptmbcinfo;
    pthreadlocinfo ptlocinfo;
    int _ownlocale;
    ulong _NLG_dwCode;
    void *_terminate;
    void *_unexpected;
    void *_translator;
    void *_purecall;
    void *_curexception;
    void *_curcontext;
    int _ProcessingThrow;
    void *_curexcspec;
    void *_pFrameInfoChain;
    _setloc_struct _setloc_data;
    void *_reserved1;
    void *_reserved2;
    void *_reserved3;
    void *_reserved4;
    void *_reserved5;
    int _cxxReThrow;
    ulong __initDomain;
    int _initapartment;
};

struct __lc_time_data {
    char *wday_abbr[7];
    char *wday[7];
    char *month_abbr[12];
    char *month[12];
    char *ampm[2];
    char *ww_sdatefmt;
    char *ww_ldatefmt;
    char *ww_timefmt;
    int ww_caltype;
    int refcount;
    wchar_t *_W_wday_abbr[7];
    wchar_t *_W_wday[7];
    wchar_t *_W_month_abbr[12];
    wchar_t *_W_month[12];
    wchar_t *_W_ampm[2];
    wchar_t *_W_ww_sdatefmt;
    wchar_t *_W_ww_ldatefmt;
    wchar_t *_W_ww_timefmt;
    wchar_t *_W_ww_locale_name;
};

typedef struct EHRegistrationNode EHRegistrationNode, *PEHRegistrationNode;

struct EHRegistrationNode { // PlaceHolder Structure
};

typedef struct _s_CatchableType _s_CatchableType, *P_s_CatchableType;

struct _s_CatchableType { // PlaceHolder Structure
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef enum _EXCEPTION_DISPOSITION {
} _EXCEPTION_DISPOSITION;

typedef struct PMD PMD, *PPMD;

struct PMD { // PlaceHolder Structure
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

struct _s_FuncInfo { // PlaceHolder Structure
};

typedef struct EHExceptionRecord EHExceptionRecord, *PEHExceptionRecord;

struct EHExceptionRecord { // PlaceHolder Structure
};

typedef struct ios ios, *Pios;

struct ios { // PlaceHolder Structure
};

typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

struct _s_HandlerType { // PlaceHolder Structure
};

typedef struct TranslatorGuardRN TranslatorGuardRN, *PTranslatorGuardRN;

struct TranslatorGuardRN { // PlaceHolder Structure
};

typedef struct MidiInterfaceClass MidiInterfaceClass, *PMidiInterfaceClass;

struct MidiInterfaceClass { // PlaceHolder Structure
};

typedef int (*_onexit_t)(void);

typedef uint size_t;

typedef struct localeinfo_struct localeinfo_struct, *Plocaleinfo_struct;

struct localeinfo_struct {
    pthreadlocinfo locinfo;
    pthreadmbcinfo mbcinfo;
};

typedef int intptr_t;

typedef struct localeinfo_struct *_locale_t;




// public: __thiscall MidiInterfaceClass::MidiInterfaceClass(void)

MidiInterfaceClass * __thiscall MidiInterfaceClass::MidiInterfaceClass(MidiInterfaceClass *this)

{
                    // 0x1000  2  ??0MidiInterfaceClass@@QAE@XZ
  *(undefined ***)this = &_vftable_;
  return this;
}



undefined4 __fastcall thunk_FUN_100021ce(int param_1)

{
  MMRESULT MVar1;
  undefined4 uVar2;
  timecaps_tag tStack_c;
  
  MVar1 = timeGetDevCaps(&tStack_c,8);
  if (MVar1 == 0) {
    *(UINT *)(param_1 + 0x14) = tStack_c.wPeriodMin;
    if (*(uint *)(param_1 + 0x14) < 10) {
      *(undefined4 *)(param_1 + 0x14) = 10;
    }
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



undefined4 thunk_FUN_10001b25(undefined4 param_1,int param_2)

{
  if (param_2 == 0) {
    DAT_10014c44 = 0;
  }
  else if (param_2 == 1) {
    DAT_10014c44 = param_1;
  }
  return 1;
}



undefined4 __fastcall thunk_FUN_1000239c(int param_1)

{
  MMRESULT MVar1;
  byte bStack_c;
  DWORD DStack_8;
  
  DStack_8 = 0x79b0;
  bStack_c = 0;
  while( true ) {
    if (0xf < bStack_c) {
      return 1;
    }
    MVar1 = midiOutShortMsg(*(HMIDIOUT *)(param_1 + 8),DStack_8);
    if (MVar1 != 0) break;
    DStack_8 = DStack_8 + 1;
    bStack_c = bStack_c + 1;
  }
  return 0;
}



int * __thiscall thunk_FUN_10001698(void *this,byte param_1)

{
  undefined4 *puVar1;
  
  *(undefined4 *)this = 1;
  puVar1 = (undefined4 *)thunk_FUN_1000123a(&DAT_100180a8,param_1);
  if (puVar1 != (undefined4 *)0x0) {
    *(undefined4 *)((int)this + 8) = *puVar1;
    *(undefined4 *)((int)this + 0xc) = puVar1[1];
    *(undefined4 *)((int)this + 0x10) = puVar1[2];
    *(undefined4 *)((int)this + 0x14) = puVar1[3];
    if (*(int *)((int)this + 0xc) != 0) {
      *(undefined4 **)((int)this + 0x18) = puVar1 + 4;
      *(int *)((int)this + 0x1c) = *(int *)((int)this + 0xc) * 8 + *(int *)((int)this + 0x18) + -8;
    }
    *(undefined4 *)((int)this + 0x24) = 0x50000;
    *(undefined4 *)((int)this + 0x28) = 100;
    *(uint *)((int)this + 0x2c) =
         (uint)(*(int *)((int)this + 0x24) * *(int *)((int)this + 0x28)) / 100;
    thunk_FUN_1000179e((int *)this);
    *(undefined4 *)this = 0;
  }
  return (int *)this;
}



undefined4 * __fastcall thunk_FUN_10001c30(undefined4 *param_1)

{
  MidiInterfaceClass::MidiInterfaceClass((MidiInterfaceClass *)param_1);
  *param_1 = &PTR_LAB_10013058;
  param_1[3] = 0;
  param_1[6] = 2;
  param_1[0xd] = 0;
  param_1[8] = 1;
  return param_1;
}



undefined4 thunk_FUN_10001448(byte *param_1,byte *param_2,int param_3)

{
  byte bVar1;
  char cVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  byte *pbVar6;
  
  _memset(&DAT_10016d70,0,0xfee);
  uVar5 = 0xfee;
  uVar3 = 0;
  while( true ) {
    while( true ) {
      uVar3 = uVar3 >> 1;
      if ((uVar3 & 0x100) == 0) {
        if (param_3 == 0) {
          return 1;
        }
        uVar3 = CONCAT31(0xff,*param_2);
        param_2 = param_2 + 1;
        param_3 = param_3 + -1;
      }
      if ((uVar3 & 1) == 0) break;
      if (param_3 == 0) {
        return 1;
      }
      bVar1 = *param_2;
      param_2 = param_2 + 1;
      param_3 = param_3 + -1;
      *param_1 = bVar1;
      param_1 = param_1 + 1;
      (&DAT_10016d70)[uVar5] = bVar1;
      uVar5 = uVar5 + 1 & 0xfff;
    }
    if (param_3 == 0) {
      return 1;
    }
    bVar1 = *param_2;
    pbVar6 = param_2 + 1;
    if (param_3 == 1) break;
    param_2 = param_2 + 2;
    param_3 = param_3 + -2;
    cVar2 = (*pbVar6 & 0xf) + 3;
    uVar4 = (uint)bVar1 + (*pbVar6 & 0xf0) * 0x10;
    do {
      bVar1 = (&DAT_10016d70)[uVar4];
      uVar4 = uVar4 + 1 & 0xfff;
      *param_1 = bVar1;
      param_1 = param_1 + 1;
      (&DAT_10016d70)[uVar5] = bVar1;
      uVar5 = uVar5 + 1 & 0xfff;
      cVar2 = cVar2 + -1;
    } while (cVar2 != '\0');
  }
  return 1;
}



void __fastcall thunk_FUN_1000219e(int param_1)

{
  if (*(int *)(param_1 + 8) != 0) {
    midiOutClose(*(HMIDIOUT *)(param_1 + 8));
  }
  return;
}



int __thiscall thunk_FUN_1000123a(void *this,byte param_1)

{
  int iVar1;
  HGLOBAL pvVar2;
  byte *pbVar3;
  
                    // WARNING: Load size is inaccurate
  if (*this != 0) {
    thunk_FUN_100012e7((undefined4 *)this);
  }
  if (((uint)param_1 < *(uint *)((int)this + 8)) || (*(uint *)((int)this + 0xc) < (uint)param_1)) {
    iVar1 = 0;
  }
  else {
    pvVar2 = thunk_FUN_10001345(param_1);
    if (pvVar2 == (HGLOBAL)0x0) {
      iVar1 = 0;
    }
    else {
      pbVar3 = thunk_FUN_1000138b(pvVar2);
      if (pbVar3 == (byte *)0x0) {
        iVar1 = 0;
      }
      else {
        *(byte **)((int)this + 4) = pbVar3;
        *(undefined4 *)this = 1;
        iVar1 = *(int *)((int)this + 4);
      }
    }
  }
  return iVar1;
}



void __fastcall thunk_FUN_1000179e(int *param_1)

{
  if ((*param_1 == 0) && (param_1[3] != 0)) {
    param_1[1] = 0;
    param_1[0xe] = 0;
    param_1[8] = param_1[6] + -8;
    thunk_FUN_10001850((int)param_1);
  }
  return;
}



// public: __thiscall MidiInterfaceClass::MidiInterfaceClass(class MidiInterfaceClass const &)

MidiInterfaceClass * __thiscall
MidiInterfaceClass::MidiInterfaceClass(MidiInterfaceClass *this,MidiInterfaceClass *param_1)

{
                    // 0x1041  1  ??0MidiInterfaceClass@@QAE@ABV0@@Z
  *(undefined ***)this = &_vftable_;
  return this;
}



int __thiscall ios::width(ios *this)

{
  return *(int *)(this + 0x30);
}



undefined4 __fastcall thunk_FUN_100022e7(int param_1)

{
  MMRESULT MVar1;
  undefined4 uVar2;
  undefined auStack_44 [64];
  
  _memset(auStack_44,0,0x40);
  auStack_44._0_4_ = &DAT_10014c48;
  auStack_44._4_4_ = 0x13;
  auStack_44._8_4_ = 0x13;
  MVar1 = midiOutPrepareHeader(*(HMIDIOUT *)(param_1 + 8),(LPMIDIHDR)auStack_44,0x40);
  if (MVar1 == 0) {
    MVar1 = midiOutLongMsg(*(HMIDIOUT *)(param_1 + 8),(LPMIDIHDR)auStack_44,0x40);
    if (MVar1 == 0) {
      do {
      } while ((auStack_44[16] & 1) == 0);
      MVar1 = midiOutUnprepareHeader(*(HMIDIOUT *)(param_1 + 8),(LPMIDIHDR)auStack_44,0x40);
      if (MVar1 == 0) {
        uVar2 = 1;
      }
      else {
        uVar2 = 0;
      }
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



undefined4 __fastcall thunk_FUN_10001895(int param_1)

{
  if (*(int *)(param_1 + 0x1c) == *(int *)(param_1 + 0x20)) {
    if (*(int *)(param_1 + 0x10) == 0) {
      *(undefined4 *)(param_1 + 4) = 1;
      return 0;
    }
    *(int *)(param_1 + 0x20) = *(int *)(param_1 + 0x14) * 8 + *(int *)(param_1 + 0x18);
    *(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(param_1 + 0x38);
  }
  else {
    *(int *)(param_1 + 0x20) = *(int *)(param_1 + 0x20) + 8;
    *(uint *)(param_1 + 0x30) =
         *(int *)(param_1 + 0x38) +
         (uint)(**(int **)(param_1 + 0x20) * *(int *)(param_1 + 0x2c)) / *(uint *)(param_1 + 8);
  }
  *(undefined4 *)(param_1 + 0x34) = *(undefined4 *)(*(int *)(param_1 + 0x20) + 4);
  return 1;
}



void __fastcall thunk_FUN_10001210(int *param_1)

{
  if (*param_1 != 0) {
    thunk_FUN_100012e7(param_1);
  }
  return;
}



undefined4 thunk_FUN_10001b10(void)

{
  return DAT_10014c44;
}



// public: class MidiInterfaceClass & __thiscall MidiInterfaceClass::operator=(class
// MidiInterfaceClass const &)

MidiInterfaceClass * __thiscall
MidiInterfaceClass::operator=(MidiInterfaceClass *this,MidiInterfaceClass *param_1)

{
                    // 0x1064  3  ??4MidiInterfaceClass@@QAEAAV0@ABV0@@Z
  return this;
}



undefined4 __fastcall thunk_FUN_10002b40(undefined4 *param_1)

{
  return *param_1;
}



HGLOBAL thunk_FUN_10001345(byte param_1)

{
  HMODULE hModule;
  HRSRC hResInfo;
  HGLOBAL pvVar1;
  
  hModule = (HMODULE)thunk_FUN_10001b10();
  hResInfo = FindResourceA(hModule,(LPCSTR)(uint)param_1,(LPCSTR)&lpType_10014c40);
  pvVar1 = LoadResource(hModule,hResInfo);
  return pvVar1;
}



bool __fastcall thunk_FUN_10002151(int param_1)

{
  MMRESULT MVar1;
  tagMIDIOUTCAPSA tStack_38;
  
  midiOutGetDevCapsA(0xffffffff,&tStack_38,0x34);
  MVar1 = midiOutOpen((LPHMIDIOUT)(param_1 + 8),0xffffffff,0,0,0);
  return MVar1 == 0;
}



undefined4 __fastcall thunk_FUN_10002bd0(int param_1)

{
  return *(undefined4 *)(param_1 + 0x34);
}



undefined4 __fastcall thunk_FUN_10002400(int param_1)

{
  MMRESULT MVar1;
  byte bStack_c;
  DWORD DStack_8;
  
  if (*(int *)(param_1 + 0x30) == 0) {
    MVar1 = midiOutReset(*(HMIDIOUT *)(param_1 + 8));
    if (MVar1 != 0) {
      return 0;
    }
  }
  else {
    DStack_8 = 0x7bb0;
    for (bStack_c = 0; bStack_c < 0x10; bStack_c = bStack_c + 1) {
      MVar1 = midiOutShortMsg(*(HMIDIOUT *)(param_1 + 8),DStack_8);
      if (MVar1 != 0) {
        return 0;
      }
      DStack_8 = DStack_8 + 1;
    }
  }
  return 1;
}



byte * thunk_FUN_1000138b(HGLOBAL param_1)

{
  int *piVar1;
  byte *pMem;
  HGLOBAL pvVar2;
  int iVar3;
  
  piVar1 = (int *)LockResource(param_1);
  if (piVar1 == (int *)0x0) {
    pMem = (byte *)0x0;
  }
  else {
    iVar3 = *piVar1;
    pvVar2 = GlobalAlloc(0,piVar1[1]);
    pMem = (byte *)GlobalLock(pvVar2);
    if (pMem == (byte *)0x0) {
      pMem = (byte *)0x0;
    }
    else {
      iVar3 = thunk_FUN_10001448(pMem,(byte *)(piVar1 + 2),iVar3);
      if (iVar3 == 0) {
        pvVar2 = GlobalHandle(pMem);
        GlobalUnlock(pvVar2);
        pvVar2 = GlobalHandle(pMem);
        GlobalFree(pvVar2);
        pMem = (byte *)0x0;
      }
    }
  }
  return pMem;
}



undefined4 __fastcall thunk_FUN_10001fac(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  if (*(int *)(param_1 + 0x34) == 1) {
    uVar1 = 1;
  }
  else if (*(int *)(param_1 + 0x34) == 0) {
    uVar1 = 0;
  }
  else {
    iVar2 = thunk_FUN_10002299(param_1);
    if (iVar2 == 0) {
      uVar1 = 0;
    }
    else {
      iVar2 = thunk_FUN_10002400(param_1);
      if (iVar2 == 0) {
        uVar1 = 0;
      }
      else {
        uVar1 = 1;
      }
    }
  }
  return uVar1;
}



void __fastcall thunk_FUN_10002604(int param_1)

{
  *(undefined4 *)(param_1 + 0x1c) = 1;
  PostMessageA(*(HWND *)(param_1 + 4),0x464,0,0);
  return;
}



void __fastcall thunk_FUN_10001c82(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_10013058;
  if (param_1[3] != 0) {
    if (param_1[0xd] != 0) {
      thunk_FUN_10001fac((int)param_1);
      if ((void *)param_1[0xe] != (void *)0x0) {
        thunk_FUN_10002a60((void *)param_1[0xe],1);
      }
    }
    thunk_FUN_1000219e((int)param_1);
  }
  return;
}



void thunk_FUN_1000177e(void)

{
  thunk_FUN_100012e7((undefined4 *)&DAT_100180a8);
  return;
}



void * __thiscall thunk_FUN_10002a60(void *this,byte param_1)

{
  thunk_FUN_1000177e();
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



undefined * GetMidiInterface(void)

{
                    // 0x10aa  5  GetMidiInterface
  return &DAT_100180c0;
}



undefined4 * __fastcall thunk_FUN_100011d0(undefined4 *param_1)

{
  param_1[2] = 1;
  param_1[3] = 0x70;
  *param_1 = 0;
  param_1[1] = 0;
  return param_1;
}



undefined4 __fastcall thunk_FUN_10001946(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  
  uVar1 = *(uint *)(param_1 + 0x34) >> 0x18;
  if (uVar1 == 0) {
    *(undefined4 *)(param_1 + 0x38) = 0;
    uVar2 = 0;
  }
  else if (uVar1 == 1) {
    *(undefined4 *)(param_1 + 0x38) = *(undefined4 *)(param_1 + 0x30);
    *(uint *)(param_1 + 0x24) = *(uint *)(param_1 + 0x34) & 0xffffff;
    *(uint *)(param_1 + 0x2c) = (uint)(*(int *)(param_1 + 0x24) * *(int *)(param_1 + 0x28)) / 100;
    uVar2 = 1;
  }
  else if (uVar1 == 2) {
    *(undefined4 *)(param_1 + 0x38) = *(undefined4 *)(param_1 + 0x30);
    uVar2 = 1;
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}



bool __fastcall thunk_FUN_10002224(DWORD_PTR param_1)

{
  MMRESULT MVar1;
  bool bVar2;
  
  timeBeginPeriod(*(UINT *)(param_1 + 0x18));
  MVar1 = timeSetEvent(*(UINT *)(param_1 + 0x14),*(UINT *)(param_1 + 0x18),&fptc_1000106e,param_1,0)
  ;
  *(MMRESULT *)(param_1 + 0x10) = MVar1;
  bVar2 = *(int *)(param_1 + 0x10) != 0;
  if (bVar2) {
    *(undefined4 *)(param_1 + 0x1c) = 0;
    *(undefined4 *)(param_1 + 0x20) = 0;
  }
  return bVar2;
}



undefined4 __fastcall thunk_FUN_10002b70(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



void __fastcall thunk_FUN_100024ac(DWORD_PTR param_1)

{
  DWORD DVar1;
  uint uVar2;
  int iVar3;
  MMRESULT MVar4;
  uint uStack_8;
  
  timeKillEvent(*(UINT *)(param_1 + 0x10));
  DVar1 = timeGetTime();
  *(DWORD *)(param_1 + 0x28) = DVar1;
  uStack_8 = (*(int *)(param_1 + 0x28) - *(int *)(param_1 + 0x24)) * 1000;
  if ((uint)(*(int *)(param_1 + 0x14) * 5000) < uStack_8) {
    uStack_8 = *(int *)(param_1 + 0x14) * 1000;
  }
  *(int *)(param_1 + 0x2c) = *(int *)(param_1 + 0x2c) + uStack_8;
  *(undefined4 *)(param_1 + 0x24) = *(undefined4 *)(param_1 + 0x28);
  do {
    uVar2 = ios::width(*(ios **)(param_1 + 0x38));
    if (*(uint *)(param_1 + 0x2c) < uVar2) {
LAB_100025ac:
      if (*(int *)(param_1 + 0x1c) == 0) {
        MVar4 = timeSetEvent(*(UINT *)(param_1 + 0x14),*(UINT *)(param_1 + 0x18),&fptc_1000106e,
                             param_1,0);
        *(MMRESULT *)(param_1 + 0x10) = MVar4;
      }
      else {
        timeEndPeriod(*(UINT *)(param_1 + 0x18));
        *(undefined4 *)(param_1 + 0x20) = 1;
      }
      return;
    }
    DVar1 = thunk_FUN_10002bd0(*(int *)(param_1 + 0x38));
    midiOutShortMsg(*(HMIDIOUT *)(param_1 + 8),DVar1);
    thunk_FUN_10001850(*(int *)(param_1 + 0x38));
    iVar3 = thunk_FUN_10002b70(*(int *)(param_1 + 0x38));
    if (iVar3 != 0) {
      thunk_FUN_10002604(param_1);
      goto LAB_100025ac;
    }
    *(int *)(param_1 + 0x2c) = *(int *)(param_1 + 0x2c) - uVar2;
  } while( true );
}



undefined4 __fastcall thunk_FUN_10002299(int param_1)

{
  if (*(int *)(param_1 + 0x20) == 0) {
    *(undefined4 *)(param_1 + 0x1c) = 1;
    do {
    } while (*(int *)(param_1 + 0x20) == 0);
  }
  return 1;
}



void __fastcall thunk_FUN_100012e7(undefined4 *param_1)

{
  HGLOBAL pvVar1;
  
  if (param_1[1] != 0) {
    pvVar1 = GlobalHandle((LPCVOID)param_1[1]);
    GlobalUnlock(pvVar1);
    pvVar1 = GlobalHandle((LPCVOID)param_1[1]);
    GlobalFree(pvVar1);
  }
  param_1[1] = 0;
  *param_1 = 0;
  return;
}



void __thiscall thunk_FUN_10001802(void *this,int param_1)

{
                    // WARNING: Load size is inaccurate
  if (*this == 0) {
    *(int *)((int)this + 0x28) = param_1;
    *(uint *)((int)this + 0x2c) =
         (uint)(*(int *)((int)this + 0x24) * *(int *)((int)this + 0x28)) / 100;
  }
  return;
}



void __fastcall thunk_FUN_10001850(int param_1)

{
  int iVar1;
  
  do {
    iVar1 = thunk_FUN_10001895(param_1);
    if (iVar1 == 0) {
      return;
    }
    iVar1 = thunk_FUN_10001946(param_1);
  } while (iVar1 != 0);
  return;
}



undefined4 * __fastcall FUN_100011d0(undefined4 *param_1)

{
  param_1[2] = 1;
  param_1[3] = 0x70;
  *param_1 = 0;
  param_1[1] = 0;
  return param_1;
}



void __fastcall FUN_10001210(int *param_1)

{
  if (*param_1 != 0) {
    thunk_FUN_100012e7(param_1);
  }
  return;
}



int __thiscall FUN_1000123a(void *this,byte param_1)

{
  int iVar1;
  HGLOBAL pvVar2;
  byte *pbVar3;
  
                    // WARNING: Load size is inaccurate
  if (*this != 0) {
    thunk_FUN_100012e7((undefined4 *)this);
  }
  if (((uint)param_1 < *(uint *)((int)this + 8)) || (*(uint *)((int)this + 0xc) < (uint)param_1)) {
    iVar1 = 0;
  }
  else {
    pvVar2 = thunk_FUN_10001345(param_1);
    if (pvVar2 == (HGLOBAL)0x0) {
      iVar1 = 0;
    }
    else {
      pbVar3 = thunk_FUN_1000138b(pvVar2);
      if (pbVar3 == (byte *)0x0) {
        iVar1 = 0;
      }
      else {
        *(byte **)((int)this + 4) = pbVar3;
        *(undefined4 *)this = 1;
        iVar1 = *(int *)((int)this + 4);
      }
    }
  }
  return iVar1;
}



void __fastcall FUN_100012e7(undefined4 *param_1)

{
  HGLOBAL pvVar1;
  
  if (param_1[1] != 0) {
    pvVar1 = GlobalHandle((LPCVOID)param_1[1]);
    GlobalUnlock(pvVar1);
    pvVar1 = GlobalHandle((LPCVOID)param_1[1]);
    GlobalFree(pvVar1);
  }
  param_1[1] = 0;
  *param_1 = 0;
  return;
}



HGLOBAL FUN_10001345(byte param_1)

{
  HMODULE hModule;
  HRSRC hResInfo;
  HGLOBAL pvVar1;
  
  hModule = (HMODULE)thunk_FUN_10001b10();
  hResInfo = FindResourceA(hModule,(LPCSTR)(uint)param_1,(LPCSTR)&lpType_10014c40);
  pvVar1 = LoadResource(hModule,hResInfo);
  return pvVar1;
}



byte * FUN_1000138b(HGLOBAL param_1)

{
  int *piVar1;
  byte *pMem;
  HGLOBAL pvVar2;
  int iVar3;
  
  piVar1 = (int *)LockResource(param_1);
  if (piVar1 == (int *)0x0) {
    pMem = (byte *)0x0;
  }
  else {
    iVar3 = *piVar1;
    pvVar2 = GlobalAlloc(0,piVar1[1]);
    pMem = (byte *)GlobalLock(pvVar2);
    if (pMem == (byte *)0x0) {
      pMem = (byte *)0x0;
    }
    else {
      iVar3 = thunk_FUN_10001448(pMem,(byte *)(piVar1 + 2),iVar3);
      if (iVar3 == 0) {
        pvVar2 = GlobalHandle(pMem);
        GlobalUnlock(pvVar2);
        pvVar2 = GlobalHandle(pMem);
        GlobalFree(pvVar2);
        pMem = (byte *)0x0;
      }
    }
  }
  return pMem;
}



undefined4 FUN_10001448(byte *param_1,byte *param_2,int param_3)

{
  byte bVar1;
  char cVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  byte *pbVar6;
  
  _memset(&DAT_10016d70,0,0xfee);
  uVar5 = 0xfee;
  uVar3 = 0;
  while( true ) {
    while( true ) {
      uVar3 = uVar3 >> 1;
      if ((uVar3 & 0x100) == 0) {
        if (param_3 == 0) {
          return 1;
        }
        uVar3 = CONCAT31(0xff,*param_2);
        param_2 = param_2 + 1;
        param_3 = param_3 + -1;
      }
      if ((uVar3 & 1) == 0) break;
      if (param_3 == 0) {
        return 1;
      }
      bVar1 = *param_2;
      param_2 = param_2 + 1;
      param_3 = param_3 + -1;
      *param_1 = bVar1;
      param_1 = param_1 + 1;
      (&DAT_10016d70)[uVar5] = bVar1;
      uVar5 = uVar5 + 1 & 0xfff;
    }
    if (param_3 == 0) {
      return 1;
    }
    bVar1 = *param_2;
    pbVar6 = param_2 + 1;
    if (param_3 == 1) break;
    param_2 = param_2 + 2;
    param_3 = param_3 + -2;
    cVar2 = (*pbVar6 & 0xf) + 3;
    uVar4 = (uint)bVar1 + (*pbVar6 & 0xf0) * 0x10;
    do {
      bVar1 = (&DAT_10016d70)[uVar4];
      uVar4 = uVar4 + 1 & 0xfff;
      *param_1 = bVar1;
      param_1 = param_1 + 1;
      (&DAT_10016d70)[uVar5] = bVar1;
      uVar5 = uVar5 + 1 & 0xfff;
      cVar2 = cVar2 + -1;
    } while (cVar2 != '\0');
  }
  return 1;
}



// Library Function - Multiple Matches With Different Base Names
//  _$E26
//  _$E31
//  _$E353
//  _$E354
// 
// Library: Visual Studio 1998 Debug

void FID_conflict___E31(void)

{
  FUN_1000162a();
  FUN_10001644();
  return;
}



void FUN_1000162a(void)

{
  thunk_FUN_100011d0((undefined4 *)&DAT_100180a8);
  return;
}



void FUN_10001644(void)

{
  _atexit(FUN_10001661);
  return;
}



void FUN_10001661(void)

{
  if ((DAT_100180b8 & 1) == 0) {
    DAT_100180b8 = DAT_100180b8 | 1;
    thunk_FUN_10001210((int *)&DAT_100180a8);
  }
  return;
}



int * __thiscall FUN_10001698(void *this,byte param_1)

{
  undefined4 *puVar1;
  
  *(undefined4 *)this = 1;
  puVar1 = (undefined4 *)thunk_FUN_1000123a(&DAT_100180a8,param_1);
  if (puVar1 != (undefined4 *)0x0) {
    *(undefined4 *)((int)this + 8) = *puVar1;
    *(undefined4 *)((int)this + 0xc) = puVar1[1];
    *(undefined4 *)((int)this + 0x10) = puVar1[2];
    *(undefined4 *)((int)this + 0x14) = puVar1[3];
    if (*(int *)((int)this + 0xc) != 0) {
      *(undefined4 **)((int)this + 0x18) = puVar1 + 4;
      *(int *)((int)this + 0x1c) = *(int *)((int)this + 0xc) * 8 + *(int *)((int)this + 0x18) + -8;
    }
    *(undefined4 *)((int)this + 0x24) = 0x50000;
    *(undefined4 *)((int)this + 0x28) = 100;
    *(uint *)((int)this + 0x2c) =
         (uint)(*(int *)((int)this + 0x24) * *(int *)((int)this + 0x28)) / 100;
    thunk_FUN_1000179e((int *)this);
    *(undefined4 *)this = 0;
  }
  return (int *)this;
}



void FUN_1000177e(void)

{
  thunk_FUN_100012e7((undefined4 *)&DAT_100180a8);
  return;
}



void __fastcall FUN_1000179e(int *param_1)

{
  if ((*param_1 == 0) && (param_1[3] != 0)) {
    param_1[1] = 0;
    param_1[0xe] = 0;
    param_1[8] = param_1[6] + -8;
    thunk_FUN_10001850((int)param_1);
  }
  return;
}



void __thiscall FUN_10001802(void *this,int param_1)

{
                    // WARNING: Load size is inaccurate
  if (*this == 0) {
    *(int *)((int)this + 0x28) = param_1;
    *(uint *)((int)this + 0x2c) =
         (uint)(*(int *)((int)this + 0x24) * *(int *)((int)this + 0x28)) / 100;
  }
  return;
}



void __fastcall FUN_10001850(int param_1)

{
  int iVar1;
  
  do {
    iVar1 = thunk_FUN_10001895(param_1);
    if (iVar1 == 0) {
      return;
    }
    iVar1 = thunk_FUN_10001946(param_1);
  } while (iVar1 != 0);
  return;
}



undefined4 __fastcall FUN_10001895(int param_1)

{
  if (*(int *)(param_1 + 0x1c) == *(int *)(param_1 + 0x20)) {
    if (*(int *)(param_1 + 0x10) == 0) {
      *(undefined4 *)(param_1 + 4) = 1;
      return 0;
    }
    *(int *)(param_1 + 0x20) = *(int *)(param_1 + 0x14) * 8 + *(int *)(param_1 + 0x18);
    *(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(param_1 + 0x38);
  }
  else {
    *(int *)(param_1 + 0x20) = *(int *)(param_1 + 0x20) + 8;
    *(uint *)(param_1 + 0x30) =
         *(int *)(param_1 + 0x38) +
         (uint)(**(int **)(param_1 + 0x20) * *(int *)(param_1 + 0x2c)) / *(uint *)(param_1 + 8);
  }
  *(undefined4 *)(param_1 + 0x34) = *(undefined4 *)(*(int *)(param_1 + 0x20) + 4);
  return 1;
}



undefined4 __fastcall FUN_10001946(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  
  uVar1 = *(uint *)(param_1 + 0x34) >> 0x18;
  if (uVar1 == 0) {
    *(undefined4 *)(param_1 + 0x38) = 0;
    uVar2 = 0;
  }
  else if (uVar1 == 1) {
    *(undefined4 *)(param_1 + 0x38) = *(undefined4 *)(param_1 + 0x30);
    *(uint *)(param_1 + 0x24) = *(uint *)(param_1 + 0x34) & 0xffffff;
    *(uint *)(param_1 + 0x2c) = (uint)(*(int *)(param_1 + 0x24) * *(int *)(param_1 + 0x28)) / 100;
    uVar2 = 1;
  }
  else if (uVar1 == 2) {
    *(undefined4 *)(param_1 + 0x38) = *(undefined4 *)(param_1 + 0x30);
    uVar2 = 1;
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}



undefined4 FUN_10001b10(void)

{
  return DAT_10014c44;
}



undefined4 FUN_10001b25(undefined4 param_1,int param_2)

{
  if (param_2 == 0) {
    DAT_10014c44 = 0;
  }
  else if (param_2 == 1) {
    DAT_10014c44 = param_1;
  }
  return 1;
}



// Library Function - Multiple Matches With Different Base Names
//  _$E26
//  _$E31
//  _$E353
//  _$E354
// 
// Library: Visual Studio 1998 Debug

void FID_conflict___E31(void)

{
  FUN_10001bca();
  FUN_10001be4();
  return;
}



void FUN_10001bca(void)

{
  thunk_FUN_10001c30((undefined4 *)&DAT_100180c0);
  return;
}



void FUN_10001be4(void)

{
  _atexit(FUN_10001c01);
  return;
}



void FUN_10001c01(void)

{
  thunk_FUN_10001c82((undefined4 *)&DAT_100180c0);
  return;
}



undefined * FUN_10001c1b(void)

{
  return &DAT_100180c0;
}



undefined4 * __fastcall FUN_10001c30(undefined4 *param_1)

{
  MidiInterfaceClass::MidiInterfaceClass((MidiInterfaceClass *)param_1);
  *param_1 = &PTR_LAB_10013058;
  param_1[3] = 0;
  param_1[6] = 2;
  param_1[0xd] = 0;
  param_1[8] = 1;
  return param_1;
}



void __fastcall FUN_10001c82(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_10013058;
  if (param_1[3] != 0) {
    if (param_1[0xd] != 0) {
      thunk_FUN_10001fac((int)param_1);
      if ((void *)param_1[0xe] != (void *)0x0) {
        thunk_FUN_10002a60((void *)param_1[0xe],1);
      }
    }
    thunk_FUN_1000219e((int)param_1);
  }
  return;
}



undefined4 __thiscall FUN_10001cf8(void *this,undefined4 param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 uVar2;
  int iVar3;
  
  bVar1 = thunk_FUN_10002151((int)this);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    uVar2 = 0;
  }
  else {
    iVar3 = thunk_FUN_100021ce((int)this);
    if (iVar3 == 0) {
      uVar2 = 0;
    }
    else {
      *(undefined4 *)((int)this + 4) = param_1;
      *(undefined4 *)((int)this + 0xc) = 1;
      uVar2 = 1;
    }
  }
  return uVar2;
}



undefined4 __thiscall FUN_10001d56(void *this,char param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  void *this_00;
  undefined4 *unaff_FS_OFFSET;
  int *local_20;
  undefined4 local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10001eb2;
  local_10 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_10;
  if (*(int *)((int)this + 0xc) == 0) {
    uVar1 = 0;
  }
  else {
    if (*(int *)((int)this + 0x34) != 0) {
                    // WARNING: Load size is inaccurate
      iVar2 = (**(code **)(*this + 0xc))();
      if (iVar2 == 0) {
        uVar1 = 0;
        goto LAB_10001ebc;
      }
      if (*(void **)((int)this + 0x38) != (void *)0x0) {
        thunk_FUN_10002a60(*(void **)((int)this + 0x38),1);
      }
    }
    this_00 = operator_new(0x3c);
    local_8 = 0;
    if (this_00 == (void *)0x0) {
      local_20 = (int *)0x0;
    }
    else {
      local_20 = thunk_FUN_10001698(this_00,param_1 + (char)param_2 * '8');
    }
    local_8 = 0xffffffff;
    *(int **)((int)this + 0x38) = local_20;
    if (*(int *)((int)this + 0x38) == 0) {
      uVar1 = 0;
    }
    else {
      iVar2 = thunk_FUN_10002b40(*(undefined4 **)((int)this + 0x38));
      if (iVar2 == 0) {
        *(undefined4 *)((int)this + 0x34) = 1;
        *(int *)((int)this + 0x30) = param_2;
        uVar1 = 1;
      }
      else {
        if (*(void **)((int)this + 0x38) != (void *)0x0) {
          thunk_FUN_10002a60(*(void **)((int)this + 0x38),1);
        }
        uVar1 = 0;
      }
    }
  }
LAB_10001ebc:
  *unaff_FS_OFFSET = local_10;
  return uVar1;
}



undefined4 __fastcall FUN_10001ecd(int *param_1)

{
  bool bVar1;
  undefined4 uVar2;
  int iVar3;
  DWORD DVar4;
  undefined3 extraout_var;
  
  if (param_1[0xd] == 0) {
    uVar2 = 0;
  }
  else {
    iVar3 = (**(code **)(*param_1 + 0xc))();
    if (iVar3 == 0) {
      uVar2 = 0;
    }
    else {
      thunk_FUN_1000179e((int *)param_1[0xe]);
      iVar3 = thunk_FUN_10002b70(param_1[0xe]);
      if (iVar3 == 1) {
        thunk_FUN_10002604((int)param_1);
        uVar2 = 1;
      }
      else {
        iVar3 = thunk_FUN_100022e7((int)param_1);
        if (iVar3 == 0) {
          uVar2 = 0;
        }
        else {
          iVar3 = thunk_FUN_1000239c((int)param_1);
          if (iVar3 == 0) {
            uVar2 = 0;
          }
          else {
            DVar4 = timeGetTime();
            param_1[9] = DVar4;
            param_1[0xb] = 0;
            bVar1 = thunk_FUN_10002224((DWORD_PTR)param_1);
            if (CONCAT31(extraout_var,bVar1) == 0) {
              uVar2 = 0;
            }
            else {
              param_1[0xd] = 2;
              uVar2 = 1;
            }
          }
        }
      }
    }
  }
  return uVar2;
}



undefined4 __fastcall FUN_10001fac(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  if (*(int *)(param_1 + 0x34) == 1) {
    uVar1 = 1;
  }
  else if (*(int *)(param_1 + 0x34) == 0) {
    uVar1 = 0;
  }
  else {
    iVar2 = thunk_FUN_10002299(param_1);
    if (iVar2 == 0) {
      uVar1 = 0;
    }
    else {
      iVar2 = thunk_FUN_10002400(param_1);
      if (iVar2 == 0) {
        uVar1 = 0;
      }
      else {
        uVar1 = 1;
      }
    }
  }
  return uVar1;
}



undefined4 __fastcall FUN_10002020(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  if (*(int *)(param_1 + 0x34) == 3) {
    uVar1 = 1;
  }
  else if (*(int *)(param_1 + 0x34) == 2) {
    iVar2 = thunk_FUN_10002299(param_1);
    if (iVar2 == 0) {
      uVar1 = 0;
    }
    else {
      iVar2 = thunk_FUN_10002400(param_1);
      if (iVar2 == 0) {
        uVar1 = 0;
      }
      else {
        *(undefined4 *)(param_1 + 0x34) = 3;
        uVar1 = 1;
      }
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



undefined4 __fastcall FUN_1000209e(DWORD_PTR param_1)

{
  bool bVar1;
  undefined4 uVar2;
  DWORD DVar3;
  undefined3 extraout_var;
  
  if (*(int *)(param_1 + 0x34) == 2) {
    uVar2 = 1;
  }
  else if (*(int *)(param_1 + 0x34) == 3) {
    DVar3 = timeGetTime();
    *(DWORD *)(param_1 + 0x24) = DVar3;
    bVar1 = thunk_FUN_10002224(param_1);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      uVar2 = 0;
    }
    else {
      *(undefined4 *)(param_1 + 0x34) = 2;
      uVar2 = 1;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



bool __thiscall FUN_10002111(void *this,int param_1)

{
  bool bVar1;
  
  bVar1 = *(int *)((int)this + 0x34) != 0;
  if (bVar1) {
    thunk_FUN_10001802(*(void **)((int)this + 0x38),param_1);
  }
  return bVar1;
}



bool __fastcall FUN_10002151(int param_1)

{
  MMRESULT MVar1;
  tagMIDIOUTCAPSA local_38;
  
  midiOutGetDevCapsA(0xffffffff,&local_38,0x34);
  MVar1 = midiOutOpen((LPHMIDIOUT)(param_1 + 8),0xffffffff,0,0,0);
  return MVar1 == 0;
}



void __fastcall FUN_1000219e(int param_1)

{
  if (*(int *)(param_1 + 8) != 0) {
    midiOutClose(*(HMIDIOUT *)(param_1 + 8));
  }
  return;
}



undefined4 __fastcall FUN_100021ce(int param_1)

{
  MMRESULT MVar1;
  undefined4 uVar2;
  timecaps_tag local_c;
  
  MVar1 = timeGetDevCaps(&local_c,8);
  if (MVar1 == 0) {
    *(UINT *)(param_1 + 0x14) = local_c.wPeriodMin;
    if (*(uint *)(param_1 + 0x14) < 10) {
      *(undefined4 *)(param_1 + 0x14) = 10;
    }
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



bool __fastcall FUN_10002224(DWORD_PTR param_1)

{
  MMRESULT MVar1;
  bool bVar2;
  
  timeBeginPeriod(*(UINT *)(param_1 + 0x18));
  MVar1 = timeSetEvent(*(UINT *)(param_1 + 0x14),*(UINT *)(param_1 + 0x18),&fptc_1000106e,param_1,0)
  ;
  *(MMRESULT *)(param_1 + 0x10) = MVar1;
  bVar2 = *(int *)(param_1 + 0x10) != 0;
  if (bVar2) {
    *(undefined4 *)(param_1 + 0x1c) = 0;
    *(undefined4 *)(param_1 + 0x20) = 0;
  }
  return bVar2;
}



undefined4 __fastcall FUN_10002299(int param_1)

{
  if (*(int *)(param_1 + 0x20) == 0) {
    *(undefined4 *)(param_1 + 0x1c) = 1;
    do {
    } while (*(int *)(param_1 + 0x20) == 0);
  }
  return 1;
}



undefined4 __fastcall FUN_100022e7(int param_1)

{
  MMRESULT MVar1;
  undefined4 uVar2;
  undefined local_44 [64];
  
  _memset(local_44,0,0x40);
  local_44._0_4_ = &DAT_10014c48;
  local_44._4_4_ = 0x13;
  local_44._8_4_ = 0x13;
  MVar1 = midiOutPrepareHeader(*(HMIDIOUT *)(param_1 + 8),(LPMIDIHDR)local_44,0x40);
  if (MVar1 == 0) {
    MVar1 = midiOutLongMsg(*(HMIDIOUT *)(param_1 + 8),(LPMIDIHDR)local_44,0x40);
    if (MVar1 == 0) {
      do {
      } while ((local_44[16] & 1) == 0);
      MVar1 = midiOutUnprepareHeader(*(HMIDIOUT *)(param_1 + 8),(LPMIDIHDR)local_44,0x40);
      if (MVar1 == 0) {
        uVar2 = 1;
      }
      else {
        uVar2 = 0;
      }
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



undefined4 __fastcall FUN_1000239c(int param_1)

{
  MMRESULT MVar1;
  byte local_c;
  DWORD local_8;
  
  local_8 = 0x79b0;
  local_c = 0;
  while( true ) {
    if (0xf < local_c) {
      return 1;
    }
    MVar1 = midiOutShortMsg(*(HMIDIOUT *)(param_1 + 8),local_8);
    if (MVar1 != 0) break;
    local_8 = local_8 + 1;
    local_c = local_c + 1;
  }
  return 0;
}



undefined4 __fastcall FUN_10002400(int param_1)

{
  MMRESULT MVar1;
  byte local_c;
  DWORD local_8;
  
  if (*(int *)(param_1 + 0x30) == 0) {
    MVar1 = midiOutReset(*(HMIDIOUT *)(param_1 + 8));
    if (MVar1 != 0) {
      return 0;
    }
  }
  else {
    local_8 = 0x7bb0;
    for (local_c = 0; local_c < 0x10; local_c = local_c + 1) {
      MVar1 = midiOutShortMsg(*(HMIDIOUT *)(param_1 + 8),local_8);
      if (MVar1 != 0) {
        return 0;
      }
      local_8 = local_8 + 1;
    }
  }
  return 1;
}



void FUN_10002492(undefined4 param_1,undefined4 param_2,DWORD_PTR param_3)

{
  thunk_FUN_100024ac(param_3);
  return;
}



void __fastcall FUN_100024ac(DWORD_PTR param_1)

{
  DWORD DVar1;
  uint uVar2;
  int iVar3;
  MMRESULT MVar4;
  uint local_8;
  
  timeKillEvent(*(UINT *)(param_1 + 0x10));
  DVar1 = timeGetTime();
  *(DWORD *)(param_1 + 0x28) = DVar1;
  local_8 = (*(int *)(param_1 + 0x28) - *(int *)(param_1 + 0x24)) * 1000;
  if ((uint)(*(int *)(param_1 + 0x14) * 5000) < local_8) {
    local_8 = *(int *)(param_1 + 0x14) * 1000;
  }
  *(int *)(param_1 + 0x2c) = *(int *)(param_1 + 0x2c) + local_8;
  *(undefined4 *)(param_1 + 0x24) = *(undefined4 *)(param_1 + 0x28);
  do {
    uVar2 = ios::width(*(ios **)(param_1 + 0x38));
    if (*(uint *)(param_1 + 0x2c) < uVar2) {
LAB_100025ac:
      if (*(int *)(param_1 + 0x1c) == 0) {
        MVar4 = timeSetEvent(*(UINT *)(param_1 + 0x14),*(UINT *)(param_1 + 0x18),&fptc_1000106e,
                             param_1,0);
        *(MMRESULT *)(param_1 + 0x10) = MVar4;
      }
      else {
        timeEndPeriod(*(UINT *)(param_1 + 0x18));
        *(undefined4 *)(param_1 + 0x20) = 1;
      }
      return;
    }
    DVar1 = thunk_FUN_10002bd0(*(int *)(param_1 + 0x38));
    midiOutShortMsg(*(HMIDIOUT *)(param_1 + 8),DVar1);
    thunk_FUN_10001850(*(int *)(param_1 + 0x38));
    iVar3 = thunk_FUN_10002b70(*(int *)(param_1 + 0x38));
    if (iVar3 != 0) {
      thunk_FUN_10002604(param_1);
      goto LAB_100025ac;
    }
    *(int *)(param_1 + 0x2c) = *(int *)(param_1 + 0x2c) - uVar2;
  } while( true );
}



void __fastcall FUN_10002604(int param_1)

{
  *(undefined4 *)(param_1 + 0x1c) = 1;
  PostMessageA(*(HWND *)(param_1 + 4),0x464,0,0);
  return;
}



void * __thiscall FUN_10002a60(void *this,byte param_1)

{
  thunk_FUN_1000177e();
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



undefined4 * __fastcall FUN_10002ab0(undefined4 *param_1)

{
  *param_1 = &MidiInterfaceClass::_vftable_;
  return param_1;
}



// Library Function - Single Match
//  private: __thiscall type_info::type_info(class type_info const &)
// 
// Library: Visual Studio 1998 Debug

type_info * __thiscall type_info::type_info(type_info *this,type_info *param_1)

{
  *(undefined ***)this = &MidiInterfaceClass::_vftable_;
  return this;
}



undefined4 __fastcall FUN_10002b10(undefined4 param_1)

{
  return param_1;
}



undefined4 __fastcall FUN_10002b40(undefined4 *param_1)

{
  return *param_1;
}



undefined4 __fastcall FUN_10002b70(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



// Library Function - Single Match
//  public: int __thiscall ios::width(void)const 
// 
// Library: Visual Studio 1998 Debug

int __thiscall ios::width(ios *this)

{
  return *(int *)(this + 0x30);
}



undefined4 __fastcall FUN_10002bd0(int param_1)

{
  return *(undefined4 *)(param_1 + 0x34);
}



// Library Function - Single Match
//  _memset
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

void * __cdecl _memset(void *_Dst,int _Val,size_t _Size)

{
  uint uVar1;
  uint uVar2;
  size_t sVar3;
  uint *puVar4;
  
  if (_Size == 0) {
    return _Dst;
  }
  uVar1 = _Val & 0xff;
  puVar4 = (uint *)_Dst;
  if (3 < _Size) {
    uVar2 = -(int)_Dst & 3;
    sVar3 = _Size;
    if (uVar2 != 0) {
      sVar3 = _Size - uVar2;
      do {
        *(undefined *)puVar4 = (undefined)_Val;
        puVar4 = (uint *)((int)puVar4 + 1);
        uVar2 = uVar2 - 1;
      } while (uVar2 != 0);
    }
    uVar1 = uVar1 * 0x1010101;
    _Size = sVar3 & 3;
    uVar2 = sVar3 >> 2;
    if (uVar2 != 0) {
      for (; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar4 = uVar1;
        puVar4 = puVar4 + 1;
      }
      if (_Size == 0) {
        return _Dst;
      }
    }
  }
  do {
    *(char *)puVar4 = (char)uVar1;
    puVar4 = (uint *)((int)puVar4 + 1);
    _Size = _Size - 1;
  } while (_Size != 0);
  return _Dst;
}



// Library Function - Single Match
//  __onexit
// 
// Library: Visual Studio 1998 Debug

_onexit_t __cdecl __onexit(_onexit_t _Func)

{
  uint uVar1;
  int iVar2;
  int **ppiVar3;
  char *pcVar4;
  int *piVar5;
  
  FID_conflict___lockexit();
  uVar1 = __msize_dbg((int)DAT_10019748,2);
  if (uVar1 < (uint)((int)DAT_10019734 + (4 - (int)DAT_10019748))) {
    piVar5 = (int *)0x6a;
    pcVar4 = s_onexit_c_10014c60;
    uVar1 = 2;
    iVar2 = __msize_dbg((int)DAT_10019748,2);
    ppiVar3 = __realloc_dbg(DAT_10019748,(int *)(iVar2 + 0x10),uVar1,(int *)pcVar4,piVar5);
    if (ppiVar3 == (int **)0x0) {
      FID_conflict___lockexit();
      return (_onexit_t)0x0;
    }
    DAT_10019734 = (_onexit_t *)
                   (((int)DAT_10019734 - (int)DAT_10019748 & 0xfffffffcU) + (int)ppiVar3);
    DAT_10019748 = ppiVar3;
  }
  *DAT_10019734 = _Func;
  DAT_10019734 = DAT_10019734 + 1;
  FID_conflict___lockexit();
  return _Func;
}



// Library Function - Single Match
//  _atexit
// 
// Library: Visual Studio 1998 Debug

int __cdecl _atexit(_func_4879 *param_1)

{
  _onexit_t p_Var1;
  int iVar2;
  
  p_Var1 = __onexit((_onexit_t)param_1);
  if (p_Var1 == (_onexit_t)0x0) {
    iVar2 = -1;
  }
  else {
    iVar2 = 0;
  }
  return iVar2;
}



// Library Function - Single Match
//  ___onexitinit
// 
// Library: Visual Studio 1998 Debug

void ___onexitinit(void)

{
  DAT_10019748 = (undefined4 *)__malloc_dbg(0x80,2,0x10014c60,0xb8);
  if (DAT_10019748 == (undefined4 *)0x0) {
    __amsg_exit(0x18);
  }
  *DAT_10019748 = 0;
  DAT_10019734 = DAT_10019748;
  return;
}



// Library Function - Single Match
//  void * __cdecl operator new(unsigned int,int,char const *,int)
// 
// Library: Visual Studio 1998 Debug

void * __cdecl operator_new(uint param_1,int param_2,char *param_3,int param_4)

{
  undefined4 *puVar1;
  
  puVar1 = __nh_malloc_dbg(param_1,1,param_2,(int)param_3,param_4);
  return puVar1;
}



// Library Function - Single Match
//  void __cdecl operator delete(void *)
// 
// Library: Visual Studio 1998 Debug

void __cdecl operator_delete(void *param_1)

{
  code *pcVar1;
  uint uVar2;
  
  if (param_1 != (void *)0x0) {
    __lock(9);
    if (((((*(uint *)((int)param_1 + -0xc) & 0xffff) != 4) && (*(int *)((int)param_1 + -0xc) != 1))
        && ((*(uint *)((int)param_1 + -0xc) & 0xffff) != 2)) &&
       ((*(int *)((int)param_1 + -0xc) != 3 &&
        (uVar2 = FUN_10005fc0(2,s_dbgnew_cpp_10014c6c,0x4f,(uint *)0x0,
                              s__BLOCK_TYPE_IS_VALID_pHead_>nBlo_10014c78), uVar2 == 1)))) {
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    __free_dbg(param_1,*(int *)((int)param_1 + -0xc));
    FUN_10005cb0(9);
  }
  return;
}



// Library Function - Single Match
//  void * __cdecl operator new(unsigned int)
// 
// Library: Visual Studio 1998 Debug

void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
  pvVar1 = __nh_malloc(param_1,1);
  return pvVar1;
}



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __cdecl __global_unwind2(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x10002f68,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
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
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined4 local_14;
  int iStack_10;
  
  iStack_10 = param_1;
  puStack_18 = &LAB_10002f70;
  uStack_1c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_1c;
  while( true ) {
    iVar1 = *(int *)(param_1 + 8);
    iVar2 = *(int *)(param_1 + 0xc);
    if ((iVar2 == -1) || (iVar2 == param_2)) break;
    local_14 = *(undefined4 *)(iVar1 + iVar2 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_14;
    if (*(int *)(iVar1 + 4 + iVar2 * 0xc) == 0) {
      FUN_10003026();
      (**(code **)(iVar1 + 8 + iVar2 * 0xc))();
    }
  }
  *unaff_FS_OFFSET = uStack_1c;
  return;
}



undefined4 FUN_10002ffa(void)

{
  int iVar1;
  undefined4 uVar2;
  int *unaff_FS_OFFSET;
  
  uVar2 = 0;
  iVar1 = *unaff_FS_OFFSET;
  if ((*(undefined **)(iVar1 + 4) == &LAB_10002f70) &&
     (*(int *)(iVar1 + 8) == *(int *)(*(int *)(iVar1 + 0xc) + 0xc))) {
    uVar2 = 1;
  }
  return uVar2;
}



void __fastcall FUN_1000301d(undefined4 param_1)

{
  undefined4 in_EAX;
  undefined4 unaff_EBP;
  
  DAT_10014ca8 = param_1;
  DAT_10014ca4 = in_EAX;
  DAT_10014cac = unaff_EBP;
  return;
}



void FUN_10003026(void)

{
  undefined4 in_EAX;
  int unaff_EBP;
  
  DAT_10014ca8 = *(undefined4 *)(unaff_EBP + 8);
  DAT_10014ca4 = in_EAX;
  DAT_10014cac = unaff_EBP;
  return;
}



// Library Function - Single Match
//  void __stdcall _JumpToContinuation(void *,struct EHRegistrationNode *)
// 
// Library: Visual Studio 1998 Release

void _JumpToContinuation(void *param_1,EHRegistrationNode *param_2)

{
  undefined4 *unaff_FS_OFFSET;
  
  *unaff_FS_OFFSET = *(undefined4 *)*unaff_FS_OFFSET;
                    // WARNING: Could not recover jumptable at 0x1000306c. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)param_1)();
  return;
}



// Library Function - Single Match
//  void __stdcall _CallMemberFunction0(void *,void *)
// 
// Library: Visual Studio 1998 Release

void _CallMemberFunction0(void *param_1,void *param_2)

{
  LOCK();
  UNLOCK();
                    // WARNING: Could not recover jumptable at 0x10003085. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)param_2)();
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  void __stdcall _CallMemberFunction1(void *,void *,void *)
//  void __stdcall _CallMemberFunction2(void *,void *,void *,int)
// 
// Library: Visual Studio 1998 Release

void FID_conflict__CallMemberFunction1(undefined4 param_1,undefined *UNRECOVERED_JUMPTABLE)

{
  LOCK();
  UNLOCK();
                    // WARNING: Could not recover jumptable at 0x10003095. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  void __stdcall _CallMemberFunction1(void *,void *,void *)
//  void __stdcall _CallMemberFunction2(void *,void *,void *,int)
// 
// Library: Visual Studio 1998 Release

void FID_conflict__CallMemberFunction1(undefined4 param_1,undefined *UNRECOVERED_JUMPTABLE)

{
  LOCK();
  UNLOCK();
                    // WARNING: Could not recover jumptable at 0x100030a5. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



// Library Function - Single Match
//  void __stdcall _UnwindNestedFrames(struct EHRegistrationNode *,struct EHExceptionRecord *)
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

void _UnwindNestedFrames(EHRegistrationNode *param_1,EHExceptionRecord *param_2)

{
  undefined4 *puVar1;
  undefined4 *unaff_FS_OFFSET;
  
  puVar1 = (undefined4 *)*unaff_FS_OFFSET;
  RtlUnwind(param_1,(PVOID)0x100030dc,(PEXCEPTION_RECORD)param_2,(PVOID)0x0);
  *(uint *)(param_2 + 4) = *(uint *)(param_2 + 4) & 0xfffffffd;
  *puVar1 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = puVar1;
  return;
}



// Library Function - Single Match
//  ___CxxFrameHandler
// 
// Library: Visual Studio 1998 Release

undefined4 __cdecl
___CxxFrameHandler(int *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4)

{
  int *in_EAX;
  undefined4 uVar1;
  
  uVar1 = ___InternalCxxFrameHandler
                    (param_1,param_2,param_3,param_4,in_EAX,0,(EHRegistrationNode *)0x0,0);
  return uVar1;
}



// Library Function - Single Match
//  void * __cdecl _CallCatchBlock2(struct EHRegistrationNode *,struct _s_FuncInfo const *,void
// *,int,unsigned long)
// 
// Library: Visual Studio 1998 Release

void * __cdecl
_CallCatchBlock2(EHRegistrationNode *param_1,_s_FuncInfo *param_2,void *param_3,int param_4,
                ulong param_5)

{
  void *pvVar1;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_14;
  undefined *local_10;
  _s_FuncInfo *local_c;
  EHRegistrationNode *local_8;
  int local_4;
  
  local_c = param_2;
  local_8 = param_1;
  local_10 = &LAB_100031e0;
  local_4 = param_4 + 1;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  pvVar1 = (void *)__CallSettingFrame_12(param_3,param_1,param_5);
  *unaff_FS_OFFSET = local_14;
  return pvVar1;
}



// Library Function - Single Match
//  int __cdecl _CallSETranslator(struct EHExceptionRecord *,struct EHRegistrationNode *,void *,void
// *,struct _s_FuncInfo const *,int,struct EHRegistrationNode *)
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

int __cdecl
_CallSETranslator(EHExceptionRecord *param_1,EHRegistrationNode *param_2,void *param_3,void *param_4
                 ,_s_FuncInfo *param_5,int param_6,EHRegistrationNode *param_7)

{
  _ptiddata p_Var1;
  int *unaff_FS_OFFSET;
  undefined4 uVar2;
  EHExceptionRecord **ppEVar3;
  undefined4 *local_38;
  code *local_34;
  _s_FuncInfo *local_30;
  EHRegistrationNode *local_2c;
  int local_28;
  EHRegistrationNode *local_24;
  undefined4 local_20;
  undefined *local_1c;
  undefined *local_18;
  int local_14;
  EHExceptionRecord *local_10;
  void *local_c;
  undefined4 local_8;
  
  local_18 = &stack0xfffffffc;
  local_1c = &stack0xffffffbc;
  local_34 = TranslatorGuardHandler;
  local_30 = param_5;
  local_2c = param_2;
  local_28 = param_6;
  local_24 = param_7;
  local_14 = 0;
  local_20 = 0x100032a9;
  local_38 = (undefined4 *)*unaff_FS_OFFSET;
  *unaff_FS_OFFSET = (int)&local_38;
  local_8 = 1;
  local_10 = param_1;
  local_c = param_3;
  ppEVar3 = &local_10;
  uVar2 = *(undefined4 *)param_1;
  p_Var1 = __getptd();
  (*(code *)p_Var1->ptmbcinfo)(uVar2,ppEVar3);
  if (local_14 == 0) {
    *unaff_FS_OFFSET = (int)local_38;
  }
  else {
    *local_38 = *(undefined4 *)*unaff_FS_OFFSET;
    *unaff_FS_OFFSET = (int)local_38;
  }
  return 0;
}



// Library Function - Single Match
//  enum _EXCEPTION_DISPOSITION __cdecl TranslatorGuardHandler(struct EHExceptionRecord *,struct
// TranslatorGuardRN *,void *,void *)
// 
// Library: Visual Studio 1998 Release

_EXCEPTION_DISPOSITION __cdecl
TranslatorGuardHandler
          (EHExceptionRecord *param_1,TranslatorGuardRN *param_2,void *param_3,void *param_4)

{
  _EXCEPTION_DISPOSITION _Var1;
  
  if (((byte)param_1[4] & 0x66) != 0) {
    *(undefined4 *)(param_2 + 0x24) = 1;
    return 1;
  }
  ___InternalCxxFrameHandler
            ((int *)param_1,*(EHRegistrationNode **)(param_2 + 0xc),(_CONTEXT *)param_3,(void *)0x0,
             *(int **)(param_2 + 8),*(int *)(param_2 + 0x10),
             *(EHRegistrationNode **)(param_2 + 0x14),1);
  if (*(int *)(param_2 + 0x24) == 0) {
    _UnwindNestedFrames((EHRegistrationNode *)param_2,param_1);
  }
                    // WARNING: Could not recover jumptable at 0x1000334f. Too many branches
                    // WARNING: Treating indirect jump as call
  _Var1 = (**(code **)(param_2 + 0x18))();
  return _Var1;
}



// Library Function - Single Match
//  __purecall
// 
// Library: Visual Studio 1998 Debug

void __purecall(void)

{
  __amsg_exit(0x19);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10003380(undefined4 param_1,int param_2)

{
  HMODULE hModule;
  FARPROC pFVar1;
  int iVar2;
  uint uVar3;
  int unaff_EDI;
  
  if (param_2 == 1) {
    DAT_10014ce4 = GetVersion();
    if (DAT_10014cc4 == 0) {
      if (((char)DAT_10014ce4 == '\x03') && ((int)DAT_10014ce4 < 0)) {
        FUN_10008980(2);
      }
      hModule = GetModuleHandleA(s_kernel32_dll_10014cd0);
      if ((hModule != (HMODULE)0x0) &&
         (pFVar1 = GetProcAddress(hModule,s_IsTNT_10014cc8), pFVar1 != (FARPROC)0x0)) {
        FUN_10008980(1);
      }
    }
    FUN_10007460();
    DAT_10014cb0 = DAT_10014cb0 + 1;
    _DAT_10014cf0 = DAT_10014ce4 >> 8 & 0xff;
    DAT_10014cec = DAT_10014ce4 & 0xff;
    _DAT_10014ce8 = DAT_10014cec * 0x100 + _DAT_10014cf0;
    DAT_10014ce4 = DAT_10014ce4 >> 0x10;
    iVar2 = __mtinit();
    if (iVar2 == 0) {
      FUN_10007490();
      return 0;
    }
    DAT_1001974c = GetCommandLineA();
    DAT_10014cb4 = FUN_100086b0();
    if ((DAT_1001974c == (LPSTR)0x0) || (DAT_10014cb4 == (LPSTR)0x0)) {
      FUN_10007490();
      return 0;
    }
    FUN_100074b0();
    FUN_100083d0();
    __setargv();
    FUN_100078b0();
    __cinit(unaff_EDI);
  }
  else if (param_2 == 0) {
    if (DAT_10014cb0 < 1) {
      return 0;
    }
    DAT_10014cb0 = DAT_10014cb0 + -1;
    if (DAT_10014d1c == 0) {
      __cexit();
    }
    uVar3 = __CrtSetDbgFlag(-1);
    if ((uVar3 & 0x20) != 0) {
      __CrtDumpMemoryLeaks();
    }
    __ioterm();
    __mtterm();
    FUN_10007490();
  }
  else if (param_2 == 3) {
    __freeptd((_ptiddata)0x0);
  }
  return 1;
}



int entry(undefined4 param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  int local_8;
  
  local_8 = 1;
  if (param_2 == 1) {
    DAT_10014cb0 = DAT_10014cb0 + 1;
  }
  else if (param_2 == 0) {
    if (DAT_10014cb0 < 1) {
      return 0;
    }
    DAT_10014cb0 = DAT_10014cb0 + -1;
  }
  if ((param_2 == 1) || (param_2 == 2)) {
    if (DAT_1001975c != (code *)0x0) {
      local_8 = (*DAT_1001975c)(param_1,param_2,param_3);
    }
    if (local_8 != 0) {
      local_8 = FUN_10003380(param_1,param_2);
    }
  }
  if (local_8 != 0) {
    local_8 = thunk_FUN_10001b25(param_1,param_2);
  }
  if ((local_8 == 0) && (param_2 == 1)) {
    __mtterm();
    FUN_10007490();
  }
  if ((param_2 == 0) || (param_2 == 3)) {
    iVar1 = FUN_10003380(param_1,param_2);
    if (iVar1 == 0) {
      local_8 = 0;
    }
    if ((local_8 != 0) && (DAT_1001975c != (code *)0x0)) {
      local_8 = (*DAT_1001975c)(param_1,param_2,param_3);
    }
  }
  return local_8;
}



// Library Function - Single Match
//  __amsg_exit
// 
// Library: Visual Studio 1998 Debug

void __cdecl __amsg_exit(int param_1)

{
  if ((DAT_10014cc0 == 1) || ((DAT_10014cc0 == 0 && (DAT_10014cc4 == 1)))) {
    __FF_MSGBANNER();
  }
  FUN_10008a00(param_1);
  (*(code *)PTR___exit_10014cbc)(0xff);
  return;
}



// Library Function - Single Match
//  __cinit
// 
// Library: Visual Studio 1998 Debug

int __cdecl __cinit(int param_1)

{
  int iVar1;
  
  if (DAT_10019744 != (code *)0x0) {
    (*DAT_10019744)();
  }
  FUN_10003900((undefined **)&DAT_10014418,(undefined **)&DAT_10014628);
  iVar1 = FUN_10003900((undefined **)&DAT_10014000,(undefined **)&DAT_10014314);
  return iVar1;
}



// Library Function - Single Match
//  _exit
// 
// Library: Visual Studio 1998 Debug

void __cdecl _exit(int _Code)

{
  FUN_100037e0(_Code,0,0);
  return;
}



// Library Function - Single Match
//  __exit
// 
// Library: Visual Studio 1998 Debug

void __cdecl __exit(UINT param_1)

{
  FUN_100037e0(param_1,1,0);
  return;
}



// Library Function - Single Match
//  __cexit
// 
// Library: Visual Studio 1998 Debug

void __cdecl __cexit(void)

{
  FUN_100037e0(0,0,1);
  return;
}



// Library Function - Single Match
//  __c_exit
// 
// Library: Visual Studio 1998 Debug

void __cdecl __c_exit(void)

{
  FUN_100037e0(0,1,1);
  return;
}



void __cdecl FUN_100037e0(UINT param_1,int param_2,int param_3)

{
  uint uVar1;
  code **local_8;
  
  FID_conflict___lockexit();
  DAT_10014d1c = 1;
  DAT_10014d18 = (undefined)param_3;
  if (param_2 == 0) {
    if (DAT_10019748 != (code **)0x0) {
      local_8 = DAT_10019734;
      while (local_8 = local_8 + -1, DAT_10019748 <= local_8) {
        if (*local_8 != (code *)0x0) {
          (**local_8)();
        }
      }
    }
    FUN_10003900((undefined **)&DAT_1001472c,(undefined **)&DAT_10014934);
  }
  FUN_10003900((undefined **)&DAT_10014a38,(undefined **)&DAT_10014b3c);
  if ((DAT_10014d20 == 0) && (uVar1 = __CrtSetDbgFlag(-1), (uVar1 & 0x20) != 0)) {
    DAT_10014d20 = 1;
    __CrtDumpMemoryLeaks();
  }
  if (param_3 == 0) {
                    // WARNING: Subroutine does not return
    ExitProcess(param_1);
  }
  FID_conflict___lockexit();
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  __lockexit
//  __unlockexit
// 
// Library: Visual Studio 1998 Debug

void __cdecl FID_conflict___lockexit(void)

{
  __lock(0xd);
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  __lockexit
//  __unlockexit
// 
// Library: Visual Studio 1998 Debug

void __cdecl FID_conflict___lockexit(void)

{
  FUN_10005cb0(0xd);
  return;
}



void __cdecl FUN_10003900(undefined **param_1,undefined **param_2)

{
  for (; param_1 < param_2; param_1 = param_1 + 1) {
    if (*param_1 != (undefined *)0x0) {
      (*(code *)*param_1)();
    }
  }
  return;
}



// Library Function - Single Match
//  _malloc
// 
// Library: Visual Studio 1998 Debug

void * __cdecl _malloc(size_t _Size)

{
  undefined4 *puVar1;
  
  puVar1 = __nh_malloc_dbg(_Size,DAT_10015d50,1,0,0);
  return puVar1;
}



// Library Function - Single Match
//  __malloc_dbg
// 
// Library: Visual Studio 1998 Debug

void __cdecl __malloc_dbg(uint param_1,uint param_2,int param_3,undefined4 param_4)

{
  __nh_malloc_dbg(param_1,DAT_10015d50,param_2,param_3,param_4);
  return;
}



// Library Function - Single Match
//  __nh_malloc
// 
// Library: Visual Studio 1998 Debug

void * __cdecl __nh_malloc(size_t _Size,int _NhFlag)

{
  undefined4 *puVar1;
  
  puVar1 = __nh_malloc_dbg(_Size,_NhFlag,1,0,0);
  return puVar1;
}



// Library Function - Single Match
//  __nh_malloc_dbg
// 
// Library: Visual Studio 1998 Debug

undefined4 * __cdecl
__nh_malloc_dbg(uint param_1,int param_2,uint param_3,int param_4,undefined4 param_5)

{
  undefined4 *puVar1;
  int iVar2;
  
  while( true ) {
    __lock(9);
    puVar1 = __heap_alloc_dbg(param_1,param_3,param_4,param_5);
    FUN_10005cb0(9);
    if (puVar1 != (undefined4 *)0x0) {
      return puVar1;
    }
    if (param_2 == 0) break;
    iVar2 = __callnewh(param_1);
    if (iVar2 == 0) {
      return (undefined4 *)0x0;
    }
  }
  return (undefined4 *)0x0;
}



// Library Function - Single Match
//  __heap_alloc
// 
// Library: Visual Studio 1998 Debug

void * __cdecl __heap_alloc(size_t _Size)

{
  undefined4 *puVar1;
  
  puVar1 = __heap_alloc_dbg(_Size,1,0,0);
  return puVar1;
}



// Library Function - Single Match
//  __heap_alloc_dbg
// 
// Library: Visual Studio 1998 Debug

undefined4 * __cdecl __heap_alloc_dbg(uint param_1,uint param_2,int param_3,undefined4 param_4)

{
  code *pcVar1;
  bool bVar2;
  undefined4 *puVar3;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  int iVar7;
  
  bVar2 = false;
  if (((((byte)DAT_10014d48 & 4) != 0) && (iVar4 = __CrtCheckMemory(), iVar4 == 0)) &&
     (uVar5 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x141,(uint *)0x0,s__CrtCheckMemory___10014e38),
     uVar5 == 1)) {
    pcVar1 = (code *)swi(3);
    puVar6 = (undefined4 *)(*pcVar1)();
    return puVar6;
  }
  iVar4 = DAT_10014d4c;
  if (DAT_10014d50 == DAT_10014d4c) {
    pcVar1 = (code *)swi(3);
    puVar6 = (undefined4 *)(*pcVar1)();
    return puVar6;
  }
  iVar7 = (*(code *)PTR_FUN_10015d6c)(1,0,param_1,param_2,DAT_10014d4c,param_3,param_4);
  if (iVar7 == 0) {
    if (param_3 == 0) {
      uVar5 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,&DAT_10014dcc);
      if (uVar5 == 1) {
        pcVar1 = (code *)swi(3);
        puVar6 = (undefined4 *)(*pcVar1)();
        return puVar6;
      }
    }
    else {
      uVar5 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,
                           s_Client_hook_allocation_failure_a_10014df4);
      if (uVar5 == 1) {
        pcVar1 = (code *)swi(3);
        puVar6 = (undefined4 *)(*pcVar1)();
        return puVar6;
      }
    }
    puVar6 = (undefined4 *)0x0;
  }
  else {
    if (((param_2 & 0xffff) != 2) && (((byte)DAT_10014d48 & 1) == 0)) {
      bVar2 = true;
    }
    if ((param_1 < 0xffffffe1) && (param_1 + 0x24 < 0xffffffe1)) {
      if (((((param_2 & 0xffff) != 4) && (param_2 != 1)) && ((param_2 & 0xffff) != 2)) &&
         ((param_2 != 3 &&
          (uVar5 = FUN_10005fc0(1,(undefined *)0x0,0,(uint *)0x0,&DAT_10014dcc), uVar5 == 1)))) {
        pcVar1 = (code *)swi(3);
        puVar6 = (undefined4 *)(*pcVar1)();
        return puVar6;
      }
      puVar6 = (undefined4 *)FUN_10008e60(param_1 + 0x24);
      if (puVar6 == (undefined4 *)0x0) {
        puVar6 = (undefined4 *)0x0;
      }
      else {
        DAT_10014d4c = DAT_10014d4c + 1;
        if (bVar2) {
          *puVar6 = 0;
          puVar6[1] = 0;
          puVar6[2] = 0;
          puVar6[3] = 0xfedcbabc;
          puVar6[4] = param_1;
          puVar6[5] = 3;
          puVar6[6] = 0;
        }
        else {
          DAT_1001810c = DAT_1001810c + param_1;
          DAT_10018118 = DAT_10018118 + param_1;
          if (DAT_10018108 < DAT_10018118) {
            DAT_10018108 = DAT_10018118;
          }
          puVar3 = puVar6;
          if (DAT_10018114 != (undefined4 *)0x0) {
            DAT_10018114[1] = puVar6;
            puVar3 = DAT_10018110;
          }
          DAT_10018110 = puVar3;
          *puVar6 = DAT_10018114;
          puVar6[1] = 0;
          puVar6[2] = param_3;
          puVar6[3] = param_4;
          puVar6[4] = param_1;
          puVar6[5] = param_2;
          puVar6[6] = iVar4;
          DAT_10018114 = puVar6;
        }
        _memset(puVar6 + 7,(uint)DAT_10014d54,4);
        _memset((void *)((int)puVar6 + param_1 + 0x20),(uint)DAT_10014d54,4);
        _memset(puVar6 + 8,(uint)DAT_10014d5c,param_1);
        puVar6 = puVar6 + 8;
      }
    }
    else {
      uVar5 = FUN_10005fc0(1,(undefined *)0x0,0,(uint *)0x0,
                           s_Invalid_allocation_size___u_byte_10014da8);
      if (uVar5 == 1) {
        pcVar1 = (code *)swi(3);
        puVar6 = (undefined4 *)(*pcVar1)();
        return puVar6;
      }
      puVar6 = (undefined4 *)0x0;
    }
  }
  return puVar6;
}



// Library Function - Single Match
//  _calloc
// 
// Library: Visual Studio 1998 Debug

void * __cdecl _calloc(size_t _Count,size_t _Size)

{
  undefined *puVar1;
  
  puVar1 = __calloc_dbg(_Count,_Size,1,0,0);
  return puVar1;
}



// Library Function - Single Match
//  __calloc_dbg
// 
// Library: Visual Studio 1998 Debug

undefined * __cdecl
__calloc_dbg(int param_1,int param_2,uint param_3,int param_4,undefined4 param_5)

{
  undefined *puVar1;
  undefined *local_8;
  
  puVar1 = (undefined *)__malloc_dbg(param_2 * param_1,param_3,param_4,param_5);
  if (puVar1 != (undefined *)0x0) {
    for (local_8 = puVar1; local_8 < puVar1 + param_2 * param_1; local_8 = local_8 + 1) {
      *local_8 = 0;
    }
  }
  return puVar1;
}



// Library Function - Multiple Matches With Different Base Names
//  __expand
//  _realloc
// 
// Library: Visual Studio 1998 Debug

void * __cdecl FID_conflict___expand(void *_Memory,size_t _NewSize)

{
  int **ppiVar1;
  
  ppiVar1 = __realloc_dbg(_Memory,(int *)_NewSize,1,(int *)0x0,(int *)0x0);
  return ppiVar1;
}



// Library Function - Single Match
//  __realloc_dbg
// 
// Library: Visual Studio 1998 Debug

int ** __cdecl __realloc_dbg(void *param_1,int *param_2,uint param_3,int *param_4,int *param_5)

{
  int **ppiVar1;
  
  __lock(9);
  ppiVar1 = _realloc_help(param_1,param_2,param_3,param_4,param_5,1);
  FUN_10005cb0(9);
  return ppiVar1;
}



// Library Function - Single Match
//  _realloc_help
// 
// Library: Visual Studio 1998 Debug

int ** __cdecl
_realloc_help(void *param_1,int *param_2,uint param_3,int *param_4,int *param_5,int param_6)

{
  code *pcVar1;
  int *piVar2;
  int **ppiVar3;
  int iVar4;
  uint uVar5;
  int **ppiVar6;
  bool bVar7;
  int **local_18;
  
  if (param_1 == (void *)0x0) {
    ppiVar3 = (int **)__malloc_dbg((uint)param_2,param_3,(int)param_4,param_5);
  }
  else if ((param_6 == 0) || (param_2 != (int *)0x0)) {
    if ((((byte)DAT_10014d48 & 4) != 0) &&
       ((iVar4 = __CrtCheckMemory(), iVar4 == 0 &&
        (uVar5 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x239,(uint *)0x0,s__CrtCheckMemory___10014e38)
        , uVar5 == 1)))) {
      pcVar1 = (code *)swi(3);
      ppiVar6 = (int **)(*pcVar1)();
      return ppiVar6;
    }
    piVar2 = DAT_10014d4c;
    if (DAT_10014d50 == DAT_10014d4c) {
      pcVar1 = (code *)swi(3);
      ppiVar6 = (int **)(*pcVar1)();
      return ppiVar6;
    }
    iVar4 = (*(code *)PTR_FUN_10015d6c)(2,param_1,param_2,param_3,DAT_10014d4c,param_4,param_5);
    if (iVar4 == 0) {
      if (param_4 == (int *)0x0) {
        uVar5 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,&DAT_10014dcc);
        if (uVar5 == 1) {
          pcVar1 = (code *)swi(3);
          ppiVar6 = (int **)(*pcVar1)();
          return ppiVar6;
        }
      }
      else {
        uVar5 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,
                             s_Client_hook_re_allocation_failur_10014fb4);
        if (uVar5 == 1) {
          pcVar1 = (code *)swi(3);
          ppiVar6 = (int **)(*pcVar1)();
          return ppiVar6;
        }
      }
      ppiVar3 = (int **)0x0;
    }
    else if (param_2 < (int *)0xffffffdc) {
      if ((((param_3 != 1) && ((param_3 & 0xffff) != 4)) && ((param_3 & 0xffff) != 2)) &&
         (uVar5 = FUN_10005fc0(1,(undefined *)0x0,0,(uint *)0x0,&DAT_10014dcc), uVar5 == 1)) {
        pcVar1 = (code *)swi(3);
        ppiVar6 = (int **)(*pcVar1)();
        return ppiVar6;
      }
      iVar4 = FUN_10005190((int)param_1);
      if ((iVar4 == 0) &&
         (uVar5 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x261,(uint *)0x0,
                               s__CrtIsValidHeapPointer_pUserData_10014f3c), uVar5 == 1)) {
        pcVar1 = (code *)swi(3);
        ppiVar6 = (int **)(*pcVar1)();
        return ppiVar6;
      }
      ppiVar6 = (int **)((int)param_1 + -0x20);
      bVar7 = *(int *)((int)param_1 + -0xc) == 3;
      if (bVar7) {
        if (((*(int *)((int)param_1 + -0x14) != -0x1234544) || (*(int *)((int)param_1 + -8) != 0))
           && (uVar5 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x26b,(uint *)0x0,
                                    s_pOldBlock_>nLine____IGNORE_LINE___10014ef4), uVar5 == 1)) {
          pcVar1 = (code *)swi(3);
          ppiVar6 = (int **)(*pcVar1)();
          return ppiVar6;
        }
      }
      else {
        if (((*(uint *)((int)param_1 + -0xc) & 0xffff) == 2) && ((param_3 & 0xffff) == 1)) {
          param_3 = 2;
        }
        if ((((*(uint *)((int)param_1 + -0xc) ^ param_3 & 0xffff) & 0xffff) != 0) &&
           (uVar5 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x272,(uint *)0x0,
                                 s__BLOCK_TYPE_pOldBlock_>nBlockUse_10014eb8), uVar5 == 1)) {
          pcVar1 = (code *)swi(3);
          ppiVar6 = (int **)(*pcVar1)();
          return ppiVar6;
        }
      }
      if (param_6 == 0) {
        local_18 = (int **)FUN_10008eb0(ppiVar6,(uint)(param_2 + 9));
        if (local_18 == (int **)0x0) {
          return (int **)0x0;
        }
      }
      else {
        local_18 = (int **)FUN_10008f00(ppiVar6,(uint)(param_2 + 9));
        if (local_18 == (int **)0x0) {
          return (int **)0x0;
        }
      }
      DAT_10014d4c = (int *)((int)DAT_10014d4c + 1);
      if (!bVar7) {
        DAT_1001810c = DAT_1001810c - (int)local_18[4];
        DAT_1001810c = DAT_1001810c + (int)param_2;
        DAT_10018118 = DAT_10018118 - (int)local_18[4];
        DAT_10018118 = DAT_10018118 + (int)param_2;
        if (DAT_10018108 < DAT_10018118) {
          DAT_10018108 = DAT_10018118;
        }
      }
      ppiVar3 = local_18 + 8;
      if (local_18[4] < param_2) {
        _memset((void *)((int)local_18[4] + (int)ppiVar3),(uint)DAT_10014d5c,
                (int)param_2 - (int)local_18[4]);
      }
      _memset((void *)((int)param_2 + (int)ppiVar3),(uint)DAT_10014d54,4);
      if (!bVar7) {
        local_18[2] = param_4;
        local_18[3] = param_5;
        local_18[6] = piVar2;
      }
      local_18[4] = param_2;
      if (((param_6 == 0) && (local_18 != ppiVar6)) &&
         (uVar5 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x2a8,(uint *)0x0,
                               s_fRealloc______fRealloc____pNewBl_10014e84), uVar5 == 1)) {
        pcVar1 = (code *)swi(3);
        ppiVar6 = (int **)(*pcVar1)();
        return ppiVar6;
      }
      if ((local_18 != ppiVar6) && (!bVar7)) {
        if (*local_18 == (int *)0x0) {
          if ((DAT_10018110 != ppiVar6) &&
             (uVar5 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x2b7,(uint *)0x0,
                                   s__pLastBlock____pOldBlock_10014e68), uVar5 == 1)) {
            pcVar1 = (code *)swi(3);
            ppiVar6 = (int **)(*pcVar1)();
            return ppiVar6;
          }
          DAT_10018110 = (int **)local_18[1];
        }
        else {
          (*local_18)[1] = (int)local_18[1];
        }
        if (local_18[1] == (int *)0x0) {
          if ((DAT_10018114 != ppiVar6) &&
             (uVar5 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x2c2,(uint *)0x0,
                                   s__pFirstBlock____pOldBlock_10014e4c), uVar5 == 1)) {
            pcVar1 = (code *)swi(3);
            ppiVar6 = (int **)(*pcVar1)();
            return ppiVar6;
          }
          DAT_10018114 = (int **)*local_18;
        }
        else {
          *local_18[1] = (int)*local_18;
        }
        if (DAT_10018114 == (int **)0x0) {
          DAT_10018110 = local_18;
        }
        else {
          DAT_10018114[1] = (int *)local_18;
        }
        *local_18 = (int *)DAT_10018114;
        local_18[1] = (int *)0x0;
        DAT_10018114 = local_18;
      }
    }
    else {
      uVar5 = FUN_10005fc0(1,(undefined *)0x0,0,(uint *)0x0,
                           s_Allocation_too_large_or_negative_10014f60);
      if (uVar5 == 1) {
        pcVar1 = (code *)swi(3);
        ppiVar6 = (int **)(*pcVar1)();
        return ppiVar6;
      }
      ppiVar3 = (int **)0x0;
    }
  }
  else {
    __free_dbg(param_1,param_3);
    ppiVar3 = (int **)0x0;
  }
  return ppiVar3;
}



// Library Function - Multiple Matches With Different Base Names
//  __expand
//  _realloc
// 
// Library: Visual Studio 1998 Debug

void * __cdecl FID_conflict___expand(void *_Memory,size_t _NewSize)

{
  int **ppiVar1;
  
  ppiVar1 = __expand_dbg(_Memory,(int *)_NewSize,1,(int *)0x0,(int *)0x0);
  return ppiVar1;
}



// Library Function - Single Match
//  __expand_dbg
// 
// Library: Visual Studio 1998 Debug

int ** __cdecl __expand_dbg(void *param_1,int *param_2,uint param_3,int *param_4,int *param_5)

{
  int **ppiVar1;
  
  __lock(9);
  ppiVar1 = _realloc_help(param_1,param_2,param_3,param_4,param_5,0);
  FUN_10005cb0(9);
  return ppiVar1;
}



void __cdecl FUN_100044f0(void *param_1)

{
  __free_dbg(param_1,1);
  return;
}



// Library Function - Single Match
//  __free_lk
// 
// Library: Visual Studio 1998 Debug

void __cdecl __free_lk(void *param_1)

{
  __free_dbg_lk(param_1,1);
  return;
}



// Library Function - Single Match
//  __free_dbg
// 
// Library: Visual Studio 1998 Debug

void __cdecl __free_dbg(void *param_1,int param_2)

{
  __lock(9);
  __free_dbg_lk(param_1,param_2);
  FUN_10005cb0(9);
  return;
}



// Library Function - Single Match
//  __free_dbg_lk
// 
// Library: Visual Studio 1998 Debug

void __cdecl __free_dbg_lk(void *param_1,int param_2)

{
  code *pcVar1;
  int iVar2;
  uint uVar3;
  int **_Dst;
  
  if (((((byte)DAT_10014d48 & 4) != 0) && (iVar2 = __CrtCheckMemory(), iVar2 == 0)) &&
     (uVar3 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x3e1,(uint *)0x0,s__CrtCheckMemory___10014e38),
     uVar3 == 1)) {
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  if (param_1 != (void *)0x0) {
    iVar2 = (*(code *)PTR_FUN_10015d6c)(3,param_1,0,param_2,0,0,0);
    if (iVar2 == 0) {
      uVar3 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,&DAT_10014dcc);
      if (uVar3 == 1) {
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
    }
    else {
      iVar2 = FUN_10005190((int)param_1);
      if ((iVar2 == 0) &&
         (uVar3 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x3f3,(uint *)0x0,
                               s__CrtIsValidHeapPointer_pUserData_10014f3c), uVar3 == 1)) {
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
      _Dst = (int **)((int)param_1 + -0x20);
      if ((((*(uint *)((int)param_1 + -0xc) & 0xffff) != 4) && (*(int *)((int)param_1 + -0xc) != 1))
         && (((*(uint *)((int)param_1 + -0xc) & 0xffff) != 2 &&
             ((*(int *)((int)param_1 + -0xc) != 3 &&
              (uVar3 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x3f9,(uint *)0x0,
                                    s__BLOCK_TYPE_IS_VALID_pHead_>nBlo_10014c78), uVar3 == 1)))))) {
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
      if (((byte)DAT_10014d48 & 4) == 0) {
        iVar2 = _CheckBytes((char *)((int)param_1 + -4),DAT_10014d54,4);
        if ((iVar2 == 0) &&
           (uVar3 = FUN_10005fc0(1,(undefined *)0x0,0,(uint *)0x0,
                                 s_DAMAGE__before__hs_block____d__a_100150a8), uVar3 == 1)) {
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
        iVar2 = _CheckBytes((char *)(*(int *)((int)param_1 + -0x10) + (int)param_1),DAT_10014d54,4);
        if ((iVar2 == 0) &&
           (uVar3 = FUN_10005fc0(1,(undefined *)0x0,0,(uint *)0x0,
                                 s_DAMAGE__after__hs_block____d__at_1001507c), uVar3 == 1)) {
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
      }
      if (*(int *)((int)param_1 + -0xc) == 3) {
        if (((*(int *)((int)param_1 + -0x14) != -0x1234544) || (*(int *)((int)param_1 + -8) != 0))
           && (uVar3 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x40e,(uint *)0x0,
                                    s_pHead_>nLine____IGNORE_LINE____p_1001503c), uVar3 == 1)) {
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
        _memset(_Dst,(uint)DAT_10014d58,*(int *)((int)param_1 + -0x10) + 0x24);
        FUN_10008fc0(_Dst);
      }
      else {
        if ((*(int *)((int)param_1 + -0xc) == 2) && (param_2 == 1)) {
          param_2 = 2;
        }
        if ((*(int *)((int)param_1 + -0xc) != param_2) &&
           (uVar3 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x41b,(uint *)0x0,
                                 s_pHead_>nBlockUse____nBlockUse_1001501c), uVar3 == 1)) {
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
        DAT_10018118 = DAT_10018118 - *(int *)((int)param_1 + -0x10);
        if (((byte)DAT_10014d48 & 2) == 0) {
          if (*_Dst == (int *)0x0) {
            if ((DAT_10018110 != _Dst) &&
               (uVar3 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x42a,(uint *)0x0,
                                     s__pLastBlock____pHead_10015004), uVar3 == 1)) {
              pcVar1 = (code *)swi(3);
              (*pcVar1)();
              return;
            }
            DAT_10018110 = *(int ***)((int)param_1 + -0x1c);
          }
          else {
            (*_Dst)[1] = *(int *)((int)param_1 + -0x1c);
          }
          if (*(int *)((int)param_1 + -0x1c) == 0) {
            if ((DAT_10018114 != _Dst) &&
               (uVar3 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x434,(uint *)0x0,
                                     s__pFirstBlock____pHead_10014fec), uVar3 == 1)) {
              pcVar1 = (code *)swi(3);
              (*pcVar1)();
              return;
            }
            DAT_10018114 = (int **)*_Dst;
          }
          else {
            **(int ***)((int)param_1 + -0x1c) = *_Dst;
          }
          _memset(_Dst,(uint)DAT_10014d58,*(int *)((int)param_1 + -0x10) + 0x24);
          FUN_10008fc0(_Dst);
        }
        else {
          *(undefined4 *)((int)param_1 + -0xc) = 0;
          _memset(param_1,(uint)DAT_10014d58,*(size_t *)((int)param_1 + -0x10));
        }
      }
    }
  }
  return;
}



// Library Function - Single Match
//  __msize
// 
// Library: Visual Studio 1998 Debug

size_t __cdecl __msize(void *_Memory)

{
  size_t sVar1;
  
  sVar1 = __msize_dbg((int)_Memory,1);
  return sVar1;
}



// Library Function - Single Match
//  __msize_dbg
// 
// Library: Visual Studio 1998 Debug

undefined4 __cdecl __msize_dbg(int param_1,int param_2)

{
  code *pcVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  
  if (((byte)DAT_10014d48 & 4) != 0) {
    iVar2 = __CrtCheckMemory();
    if (iVar2 == 0) {
      uVar3 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x47c,(uint *)0x0,s__CrtCheckMemory___10014e38);
      if (uVar3 == 1) {
        pcVar1 = (code *)swi(3);
        uVar4 = (*pcVar1)();
        return uVar4;
      }
    }
  }
  __lock(9);
  iVar2 = FUN_10005190(param_1);
  if (iVar2 == 0) {
    uVar3 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x485,(uint *)0x0,
                         s__CrtIsValidHeapPointer_pUserData_10014f3c);
    if (uVar3 == 1) {
      pcVar1 = (code *)swi(3);
      uVar4 = (*pcVar1)();
      return uVar4;
    }
  }
  if (((((*(uint *)(param_1 + -0xc) & 0xffff) != 4) && (*(int *)(param_1 + -0xc) != 1)) &&
      ((*(uint *)(param_1 + -0xc) & 0xffff) != 2)) && (*(int *)(param_1 + -0xc) != 3)) {
    uVar3 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x48b,(uint *)0x0,
                         s__BLOCK_TYPE_IS_VALID_pHead_>nBlo_10014c78);
    if (uVar3 == 1) {
      pcVar1 = (code *)swi(3);
      uVar4 = (*pcVar1)();
      return uVar4;
    }
  }
  if ((*(int *)(param_1 + -0xc) == 2) && (param_2 == 1)) {
    param_2 = 2;
  }
  if ((*(int *)(param_1 + -0xc) != 3) && (*(int *)(param_1 + -0xc) != param_2)) {
    uVar3 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x492,(uint *)0x0,
                         s_pHead_>nBlockUse____nBlockUse_1001501c);
    if (uVar3 == 1) {
      pcVar1 = (code *)swi(3);
      uVar4 = (*pcVar1)();
      return uVar4;
    }
  }
  uVar4 = *(undefined4 *)(param_1 + -0x10);
  FUN_10005cb0(9);
  return uVar4;
}



undefined4 __cdecl FUN_10004b30(undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = DAT_10014d50;
  DAT_10014d50 = param_1;
  return uVar1;
}



// Library Function - Single Match
//  __CrtSetDbgBlockType
// 
// Library: Visual Studio 1998 Debug

void __cdecl __CrtSetDbgBlockType(int param_1,undefined4 param_2)

{
  code *pcVar1;
  int iVar2;
  uint uVar3;
  
  __lock(9);
  iVar2 = FUN_10005190(param_1);
  if (iVar2 != 0) {
    if (((((*(uint *)(param_1 + -0xc) & 0xffff) != 4) && (*(int *)(param_1 + -0xc) != 1)) &&
        ((*(uint *)(param_1 + -0xc) & 0xffff) != 2)) && (*(int *)(param_1 + -0xc) != 3)) {
      uVar3 = FUN_10005fc0(2,s_dbgheap_c_10014e2c,0x4d3,(uint *)0x0,
                           s__BLOCK_TYPE_IS_VALID_pHead_>nBlo_10014c78);
      if (uVar3 == 1) {
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
    }
    *(undefined4 *)(param_1 + -0xc) = param_2;
  }
  FUN_10005cb0(9);
  return;
}



undefined * __cdecl FUN_10004c20(undefined *param_1)

{
  undefined *puVar1;
  
  puVar1 = PTR_FUN_10015d6c;
  PTR_FUN_10015d6c = param_1;
  return puVar1;
}



// Library Function - Single Match
//  _CheckBytes
// 
// Library: Visual Studio 1998 Debug

undefined4 __cdecl _CheckBytes(char *param_1,char param_2,int param_3)

{
  int iVar1;
  char *pcVar2;
  char cVar3;
  code *pcVar4;
  uint uVar5;
  undefined4 uVar6;
  undefined4 local_8;
  
  local_8 = 1;
  while( true ) {
    do {
      iVar1 = param_3 + -1;
      if (param_3 == 0) {
        return local_8;
      }
      pcVar2 = param_1 + 1;
      cVar3 = *param_1;
      param_1 = pcVar2;
      param_3 = iVar1;
    } while (cVar3 == param_2);
    uVar5 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,
                         s_memory_check_error_at_0x_08X___0_100150f0);
    if (uVar5 == 1) break;
    local_8 = 0;
  }
  pcVar4 = (code *)swi(3);
  uVar6 = (*pcVar4)();
  return uVar6;
}



// Library Function - Single Match
//  __CrtCheckMemory
// 
// Library: Visual Studio 1998 Debug

undefined4 __CrtCheckMemory(void)

{
  code *pcVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  undefined4 *local_c;
  undefined4 local_8;
  
  local_8 = 1;
  if (((byte)DAT_10014d48 & 1) == 0) {
    local_8 = 1;
  }
  else {
    __lock(9);
    iVar3 = FUN_10008ff0();
    if ((iVar3 == -1) || (iVar3 == -2)) {
      for (local_c = DAT_10018114; local_c != (undefined4 *)0x0; local_c = (undefined4 *)*local_c) {
        bVar2 = true;
        iVar3 = _CheckBytes((char *)(local_c + 7),DAT_10014d54,4);
        if (iVar3 == 0) {
          uVar4 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,
                               s_DAMAGE__before__hs_block____d__a_100150a8);
          if (uVar4 == 1) {
            pcVar1 = (code *)swi(3);
            uVar5 = (*pcVar1)();
            return uVar5;
          }
          bVar2 = false;
        }
        iVar3 = _CheckBytes((char *)((int)local_c + local_c[4] + 0x20),DAT_10014d54,4);
        if (iVar3 == 0) {
          uVar4 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,
                               s_DAMAGE__after__hs_block____d__at_1001507c);
          if (uVar4 == 1) {
            pcVar1 = (code *)swi(3);
            uVar5 = (*pcVar1)();
            return uVar5;
          }
          bVar2 = false;
        }
        if ((local_c[5] == 0) &&
           (iVar3 = _CheckBytes((char *)(local_c + 8),DAT_10014d58,local_c[4]), iVar3 == 0)) {
          uVar4 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,
                               s_DAMAGE__on_top_of_Free_block_at_0_10015178);
          if (uVar4 == 1) {
            pcVar1 = (code *)swi(3);
            uVar5 = (*pcVar1)();
            return uVar5;
          }
          bVar2 = false;
        }
        if (!bVar2) {
          if ((local_c[2] != 0) &&
             (uVar4 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,
                                   s__hs_allocated_at_file__hs__d___10015158), uVar4 == 1)) {
            pcVar1 = (code *)swi(3);
            uVar5 = (*pcVar1)();
            return uVar5;
          }
          uVar4 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,
                               s__hs_located_at_0x_08X_is__u_byte_1001512c);
          if (uVar4 == 1) {
            pcVar1 = (code *)swi(3);
            uVar5 = (*pcVar1)();
            return uVar5;
          }
          local_8 = 0;
        }
      }
      FUN_10005cb0(9);
    }
    else {
      switch(iVar3) {
      default:
        uVar4 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,&DAT_10014dcc);
        if (uVar4 == 1) {
          pcVar1 = (code *)swi(3);
          uVar5 = (*pcVar1)();
          return uVar5;
        }
        break;
      case -6:
        uVar4 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,&DAT_10014dcc);
        if (uVar4 == 1) {
          pcVar1 = (code *)swi(3);
          uVar5 = (*pcVar1)();
          return uVar5;
        }
        break;
      case -5:
        uVar4 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,&DAT_10014dcc);
        if (uVar4 == 1) {
          pcVar1 = (code *)swi(3);
          uVar5 = (*pcVar1)();
          return uVar5;
        }
        break;
      case -4:
        uVar4 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,&DAT_10014dcc);
        if (uVar4 == 1) {
          pcVar1 = (code *)swi(3);
          uVar5 = (*pcVar1)();
          return uVar5;
        }
        break;
      case -3:
        uVar4 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,&DAT_10014dcc);
        if (uVar4 == 1) {
          pcVar1 = (code *)swi(3);
          uVar5 = (*pcVar1)();
          return uVar5;
        }
      }
      FUN_10005cb0(9);
      local_8 = 0;
    }
  }
  return local_8;
}



// Library Function - Single Match
//  __CrtSetDbgFlag
// 
// Library: Visual Studio 1998 Debug

int __cdecl __CrtSetDbgFlag(int param_1)

{
  int iVar1;
  
  iVar1 = DAT_10014d48;
  if (param_1 != -1) {
    DAT_10014d48 = param_1;
  }
  return iVar1;
}



// Library Function - Single Match
//  __CrtDoForAllClientObjects
// 
// Library: Visual Studio 1998 Debug

void __cdecl __CrtDoForAllClientObjects(undefined *param_1,undefined4 param_2)

{
  undefined4 *local_8;
  
  if (((byte)DAT_10014d48 & 1) != 0) {
    __lock(9);
    for (local_8 = DAT_10018114; local_8 != (undefined4 *)0x0; local_8 = (undefined4 *)*local_8) {
      if ((local_8[5] & 0xffff) == 4) {
        (*(code *)param_1)(local_8 + 8,param_2);
      }
    }
    FUN_10005cb0(9);
  }
  return;
}



// Library Function - Single Match
//  __CrtIsValidPointer
// 
// Library: Visual Studio 1998 Debug

undefined4 __cdecl __CrtIsValidPointer(void *param_1,UINT_PTR param_2,int param_3)

{
  BOOL BVar1;
  
  if (((param_1 != (void *)0x0) && (BVar1 = IsBadReadPtr(param_1,param_2), BVar1 == 0)) &&
     ((param_3 == 0 || (BVar1 = IsBadWritePtr(param_1,param_2), BVar1 == 0)))) {
    return 1;
  }
  return 0;
}



undefined4 __cdecl FUN_10005190(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  if (param_1 == 0) {
    uVar1 = 0;
  }
  else {
    iVar2 = __CrtIsValidPointer((void *)(param_1 + -0x20),0x20,1);
    if (iVar2 == 0) {
      uVar1 = 0;
    }
    else {
      uVar1 = 1;
    }
  }
  return uVar1;
}



// Library Function - Single Match
//  __CrtIsMemoryBlock
// 
// Library: Visual Studio 1998 Debug

undefined4 __cdecl
__CrtIsMemoryBlock(void *param_1,UINT_PTR param_2,undefined4 *param_3,undefined4 *param_4,
                  undefined4 *param_5)

{
  int iVar1;
  
  iVar1 = FUN_10005190((int)param_1);
  if (iVar1 != 0) {
    __lock(9);
    if ((((((*(uint *)((int)param_1 + -0xc) & 0xffff) == 4) || (*(int *)((int)param_1 + -0xc) == 1))
         || ((*(uint *)((int)param_1 + -0xc) & 0xffff) == 2)) ||
        (*(int *)((int)param_1 + -0xc) == 3)) &&
       (((iVar1 = __CrtIsValidPointer(param_1,param_2,1), iVar1 != 0 &&
         (*(UINT_PTR *)((int)param_1 + -0x10) == param_2)) &&
        (*(int *)((int)param_1 + -8) <= DAT_10014d4c)))) {
      if (param_3 != (undefined4 *)0x0) {
        *param_3 = *(undefined4 *)((int)param_1 + -8);
      }
      if (param_4 != (undefined4 *)0x0) {
        *param_4 = *(undefined4 *)((int)param_1 + -0x18);
      }
      if (param_5 != (undefined4 *)0x0) {
        *param_5 = *(undefined4 *)((int)param_1 + -0x14);
      }
      FUN_10005cb0(9);
      return 1;
    }
    FUN_10005cb0(9);
  }
  return 0;
}



undefined4 __cdecl FUN_10005300(undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = DAT_10019728;
  DAT_10019728 = param_1;
  return uVar1;
}



// Library Function - Single Match
//  __CrtMemCheckpoint
// 
// Library: Visual Studio 1998 Debug

void __cdecl __CrtMemCheckpoint(undefined4 *param_1)

{
  code *pcVar1;
  uint uVar2;
  int local_c;
  undefined4 *local_8;
  
  if (param_1 == (undefined4 *)0x0) {
    uVar2 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,&DAT_10014dcc);
    if (uVar2 == 1) {
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
  }
  else {
    __lock(9);
    *param_1 = DAT_10018114;
    for (local_c = 0; local_c < 5; local_c = local_c + 1) {
      param_1[local_c + 6] = 0;
      param_1[local_c + 1] = param_1[local_c + 6];
    }
    for (local_8 = DAT_10018114; local_8 != (undefined4 *)0x0; local_8 = (undefined4 *)*local_8) {
      if ((local_8[5] & 0xffff) < 5) {
        param_1[(local_8[5] & 0xffff) + 1] = param_1[(local_8[5] & 0xffff) + 1] + 1;
        param_1[(local_8[5] & 0xffff) + 6] = param_1[(local_8[5] & 0xffff) + 6] + local_8[4];
      }
      else {
        uVar2 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,
                             s_Bad_memory_block_found_at_0x_08X_10015268);
        if (uVar2 == 1) {
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
      }
    }
    param_1[0xb] = DAT_10018108;
    param_1[0xc] = DAT_1001810c;
    FUN_10005cb0(9);
  }
  return;
}



// Library Function - Single Match
//  __CrtMemDifference
// 
// Library: Visual Studio 1998 Debug

undefined4 __cdecl __CrtMemDifference(undefined4 *param_1,int param_2,int param_3)

{
  code *pcVar1;
  uint uVar2;
  undefined4 uVar3;
  int local_c;
  undefined4 local_8;
  
  local_8 = 0;
  if (((param_1 == (undefined4 *)0x0) || (param_2 == 0)) || (param_3 == 0)) {
    uVar2 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,&DAT_10014dcc);
    if (uVar2 == 1) {
      pcVar1 = (code *)swi(3);
      uVar3 = (*pcVar1)();
      return uVar3;
    }
    local_8 = 0;
  }
  else {
    for (local_c = 0; local_c < 5; local_c = local_c + 1) {
      param_1[local_c + 6] =
           *(int *)(param_3 + 0x18 + local_c * 4) - *(int *)(param_2 + 0x18 + local_c * 4);
      param_1[local_c + 1] =
           *(int *)(param_3 + 4 + local_c * 4) - *(int *)(param_2 + 4 + local_c * 4);
      if (((param_1[local_c + 6] != 0) || (param_1[local_c + 1] != 0)) &&
         ((local_c != 0 && ((local_c != 2 || (((byte)DAT_10014d48 & 0x10) != 0)))))) {
        local_8 = 1;
      }
    }
    param_1[0xb] = *(int *)(param_3 + 0x2c) - *(int *)(param_2 + 0x2c);
    param_1[0xc] = *(int *)(param_3 + 0x30) - *(int *)(param_2 + 0x30);
    *param_1 = 0;
  }
  return local_8;
}



// Library Function - Single Match
//  __CrtMemDumpAllObjectsSince
// 
// Library: Visual Studio 1998 Debug

void __cdecl __CrtMemDumpAllObjectsSince(undefined4 *param_1)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  undefined4 *local_c;
  undefined4 *local_8;
  
  local_8 = (undefined4 *)0x0;
  __lock(9);
  uVar2 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,&DAT_10014dcc);
  if (uVar2 == 1) {
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  if (param_1 != (undefined4 *)0x0) {
    local_8 = (undefined4 *)*param_1;
  }
  local_c = DAT_10018114;
  do {
    if ((local_c == (undefined4 *)0x0) || (local_8 == local_c)) {
      FUN_10005cb0(9);
      uVar2 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,&DAT_10014dcc);
      if (uVar2 != 1) {
        return;
      }
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    if ((((local_c[5] & 0xffff) != 3) && ((local_c[5] & 0xffff) != 0)) &&
       (((local_c[5] & 0xffff) != 2 || (((byte)DAT_10014d48 & 0x10) != 0)))) {
      if (local_c[2] != 0) {
        iVar3 = __CrtIsValidPointer((void *)local_c[2],1,0);
        if (iVar3 == 0) {
          uVar2 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,s__File_Error___d____10015398);
          if (uVar2 == 1) {
            pcVar1 = (code *)swi(3);
            (*pcVar1)();
            return;
          }
        }
        else {
          uVar2 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,s__hs__d____1001538c);
          if (uVar2 == 1) {
            pcVar1 = (code *)swi(3);
            (*pcVar1)();
            return;
          }
        }
      }
      uVar2 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,s___ld__10015384);
      if (uVar2 == 1) {
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
      if ((local_c[5] & 0xffff) == 4) {
        uVar2 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,
                             s_client_block_at_0x_08X__subtype___10015350);
        if (uVar2 == 1) {
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
        if (DAT_10019728 == (code *)0x0) {
          __printMemBlockData((int)local_c);
        }
        else {
          (*DAT_10019728)(local_c + 8,local_c[4]);
        }
      }
      else if (local_c[5] == 1) {
        uVar2 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,
                             s_normal_block_at_0x_08X___u_bytes_10015328);
        if (uVar2 == 1) {
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
        __printMemBlockData((int)local_c);
      }
      else if ((local_c[5] & 0xffff) == 2) {
        uVar2 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,
                             s_crt_block_at_0x_08X__subtype__x__100152f4);
        if (uVar2 == 1) {
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
        __printMemBlockData((int)local_c);
      }
    }
    local_c = (undefined4 *)*local_c;
  } while( true );
}



// Library Function - Single Match
//  __printMemBlockData
// 
// Library: Visual Studio 1998 Debug

void __cdecl __printMemBlockData(int param_1)

{
  code *pcVar1;
  int iVar2;
  uint uVar3;
  uint local_58;
  char local_54 [52];
  int local_20;
  byte local_1c [20];
  byte local_8;
  
  local_20 = 0;
  while( true ) {
    iVar2 = *(int *)(param_1 + 0x10);
    if (0xf < iVar2) {
      iVar2 = 0x10;
    }
    if (iVar2 <= local_20) break;
    local_8 = *(byte *)(param_1 + 0x20 + local_20);
    if (DAT_10015fac < 2) {
      local_58 = *(ushort *)(PTR_DAT_10015da0 + (uint)local_8 * 2) & 0x157;
    }
    else {
      local_58 = __isctype((uint)local_8,0x157);
    }
    if (local_58 == 0) {
      local_1c[local_20] = 0x20;
    }
    else {
      local_1c[local_20] = local_8;
    }
    _sprintf(local_54 + local_20 * 3,s___2X_100153d0,(uint)local_8);
    local_20 = local_20 + 1;
  }
  local_1c[local_20] = 0;
  uVar3 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,s__Data__<_s>__s_100153c0);
  if (uVar3 == 1) {
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  return;
}



// Library Function - Single Match
//  __CrtDumpMemoryLeaks
// 
// Library: Visual Studio 1998 Debug

undefined4 __CrtDumpMemoryLeaks(void)

{
  code *pcVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined4 local_38 [2];
  int local_30;
  int local_2c;
  int local_24;
  
  __CrtMemCheckpoint(local_38);
  if (((local_24 == 0) && (local_30 == 0)) &&
     ((((byte)DAT_10014d48 & 0x10) == 0 || (local_2c == 0)))) {
    uVar3 = 0;
  }
  else {
    uVar2 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,&DAT_10014dcc);
    if (uVar2 == 1) {
      pcVar1 = (code *)swi(3);
      uVar3 = (*pcVar1)();
      return uVar3;
    }
    __CrtMemDumpAllObjectsSince((undefined4 *)0x0);
    uVar3 = 1;
  }
  return uVar3;
}



// Library Function - Single Match
//  __CrtMemDumpStatistics
// 
// Library: Visual Studio 1998 Debug

void __cdecl __CrtMemDumpStatistics(int param_1)

{
  code *pcVar1;
  uint uVar2;
  int local_8;
  
  if (param_1 != 0) {
    for (local_8 = 0; local_8 < 5; local_8 = local_8 + 1) {
      uVar2 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,s__ld_bytes_in__ld__hs_Blocks__10015434)
      ;
      if (uVar2 == 1) {
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
    }
    uVar2 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,s_Largest_number_used___ld_bytes__10015410
                        );
    if (uVar2 == 1) {
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    uVar2 = FUN_10005fc0(0,(undefined *)0x0,0,(uint *)0x0,s_Total_allocations___ld_bytes__100153f0);
    if (uVar2 == 1) {
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
  }
  return;
}



// Library Function - Single Match
//  __mtinitlocks
// 
// Library: Visual Studio 1998 Debug

int __cdecl __mtinitlocks(void)

{
  int extraout_EAX;
  
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_1001549c);
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_1001548c);
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_1001547c);
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_1001545c);
  return extraout_EAX;
}



// Library Function - Single Match
//  __mtdeletelocks
// 
// Library: Visual Studio 1998 Debug

void __cdecl __mtdeletelocks(void)

{
  int local_8;
  
  for (local_8 = 0; local_8 < 0x30; local_8 = local_8 + 1) {
    if ((((*(int *)(&DAT_10015458 + local_8 * 4) != 0) && (local_8 != 0x11)) && (local_8 != 0xd)) &&
       ((local_8 != 9 && (local_8 != 1)))) {
      DeleteCriticalSection(*(LPCRITICAL_SECTION *)(&DAT_10015458 + local_8 * 4));
      __free_dbg(*(void **)(&DAT_10015458 + local_8 * 4),2);
    }
  }
  DeleteCriticalSection((LPCRITICAL_SECTION)PTR_DAT_1001547c);
  DeleteCriticalSection((LPCRITICAL_SECTION)PTR_DAT_1001548c);
  DeleteCriticalSection((LPCRITICAL_SECTION)PTR_DAT_1001549c);
  DeleteCriticalSection((LPCRITICAL_SECTION)PTR_DAT_1001545c);
  return;
}



// Library Function - Single Match
//  __lock
// 
// Library: Visual Studio 1998 Debug

void __cdecl __lock(int _File)

{
  LPCRITICAL_SECTION lpCriticalSection;
  
  if (*(int *)(&DAT_10015458 + _File * 4) == 0) {
    lpCriticalSection = (LPCRITICAL_SECTION)__malloc_dbg(0x18,2,0x10015518,0xe6);
    if (lpCriticalSection == (LPCRITICAL_SECTION)0x0) {
      __amsg_exit(0x11);
    }
    __lock(0x11);
    if (*(int *)(&DAT_10015458 + _File * 4) == 0) {
      InitializeCriticalSection(lpCriticalSection);
      *(LPCRITICAL_SECTION *)(&DAT_10015458 + _File * 4) = lpCriticalSection;
    }
    else {
      __free_dbg(lpCriticalSection,2);
    }
    FUN_10005cb0(0x11);
  }
  EnterCriticalSection(*(LPCRITICAL_SECTION *)(&DAT_10015458 + _File * 4));
  return;
}



void __cdecl FUN_10005cb0(int param_1)

{
  LeaveCriticalSection(*(LPCRITICAL_SECTION *)(&DAT_10015458 + param_1 * 4));
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  __lock_file
//  __unlock_file
// 
// Library: Visual Studio 1998 Debug

void __cdecl FID_conflict___lock_file(FILE *_File)

{
  if ((_File < &PTR_DAT_10015fb8) || ((FILE *)0x10016218 < _File)) {
    EnterCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  }
  else {
    __lock(((int)&_File[-0x800afe]._base >> 5) + 0x1c);
  }
  return;
}



void __cdecl FUN_10005d30(int param_1,int param_2)

{
  if (param_1 < 0x14) {
    __lock(param_1 + 0x1c);
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)(param_2 + 0x20));
  }
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  __lock_file
//  __unlock_file
// 
// Library: Visual Studio 1998 Debug

void __cdecl FID_conflict___lock_file(FILE *_File)

{
  if ((_File < &PTR_DAT_10015fb8) || ((FILE *)0x10016218 < _File)) {
    LeaveCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  }
  else {
    FUN_10005cb0(((int)&_File[-0x800afe]._base >> 5) + 0x1c);
  }
  return;
}



void __cdecl FUN_10005dd0(int param_1,int param_2)

{
  if (param_1 < 0x14) {
    FUN_10005cb0(param_1 + 0x1c);
  }
  else {
    LeaveCriticalSection((LPCRITICAL_SECTION)(param_2 + 0x20));
  }
  return;
}



// Library Function - Single Match
//  __lockerr_exit
// 
// Library: Visual Studio 1998 Debug

void __cdecl __lockerr_exit(LPCSTR param_1)

{
  FatalAppExitA(0,param_1);
                    // WARNING: Subroutine does not return
  ExitProcess(0xff);
}



void FUN_10005e40(void)

{
  DebugBreak();
  return;
}



// Library Function - Single Match
//  __CrtSetReportMode
// 
// Library: Visual Studio 1998 Debug

undefined4 __cdecl __CrtSetReportMode(int param_1,uint param_2)

{
  undefined4 uVar1;
  
  if ((param_1 < 0) || (2 < param_1)) {
    uVar1 = 0xffffffff;
  }
  else if (param_2 == 0xffffffff) {
    uVar1 = *(undefined4 *)(&DAT_10015550 + param_1 * 4);
  }
  else if ((param_2 & 0xfffffff8) == 0) {
    uVar1 = *(undefined4 *)(&DAT_10015550 + param_1 * 4);
    *(uint *)(&DAT_10015550 + param_1 * 4) = param_2;
  }
  else {
    uVar1 = 0xffffffff;
  }
  return uVar1;
}



// Library Function - Single Match
//  __CrtSetReportFile
// 
// Library: Visual Studio 1998 Debug

undefined4 __cdecl __CrtSetReportFile(int param_1,int param_2)

{
  undefined4 uVar1;
  HANDLE pvVar2;
  
  if ((param_1 < 0) || (2 < param_1)) {
    uVar1 = 0xfffffffe;
  }
  else if (param_2 == -6) {
    uVar1 = *(undefined4 *)(&DAT_10015560 + param_1 * 4);
  }
  else {
    uVar1 = *(undefined4 *)(&DAT_10015560 + param_1 * 4);
    if (param_2 == -4) {
      pvVar2 = GetStdHandle(0xfffffff5);
      *(HANDLE *)(&DAT_10015560 + param_1 * 4) = pvVar2;
    }
    else if (param_2 == -5) {
      pvVar2 = GetStdHandle(0xfffffff4);
      *(HANDLE *)(&DAT_10015560 + param_1 * 4) = pvVar2;
    }
    else {
      *(int *)(&DAT_10015560 + param_1 * 4) = param_2;
    }
  }
  return uVar1;
}



undefined4 __cdecl FUN_10005f90(undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = DAT_1001971c;
  DAT_1001971c = param_1;
  return uVar1;
}



uint __cdecl FUN_10005fc0(int param_1,undefined *param_2,int param_3,uint *param_4,char *param_5)

{
  bool bVar1;
  LONG LVar2;
  char *nNumberOfBytesToWrite;
  undefined3 extraout_var;
  int iVar3;
  undefined4 *puVar4;
  DWORD *lpNumberOfBytesWritten;
  LPOVERLAPPED lpOverlapped;
  char *local_62c;
  DWORD local_614;
  HMODULE local_610;
  undefined local_60c;
  undefined4 local_60b;
  va_list local_40c;
  undefined local_408;
  undefined4 local_407;
  uint local_208;
  undefined local_204;
  undefined4 local_203;
  
  local_204 = '\0';
  puVar4 = &local_203;
  for (iVar3 = 0x7f; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  *(undefined2 *)puVar4 = 0;
  *(undefined *)((int)puVar4 + 2) = 0;
  local_60c = '\0';
  puVar4 = &local_60b;
  for (iVar3 = 0x7f; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  *(undefined2 *)puVar4 = 0;
  *(undefined *)((int)puVar4 + 2) = 0;
  local_408 = '\0';
  puVar4 = &local_407;
  for (iVar3 = 0x7f; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  *(undefined2 *)puVar4 = 0;
  *(undefined *)((int)puVar4 + 2) = 0;
  local_40c = &stack0x00000018;
  if ((param_1 < 0) || (2 < param_1)) {
    local_208 = 0xffffffff;
  }
  else if ((param_1 == 2) && (LVar2 = InterlockedIncrement((LONG *)&lpAddend_10015548), 0 < LVar2))
  {
    if ((DAT_1001557c == (FARPROC)0x0) &&
       ((local_610 = LoadLibraryA(s_user32_dll_10015624), local_610 == (HMODULE)0x0 ||
        (DAT_1001557c = GetProcAddress(local_610,s_wsprintfA_10015618), DAT_1001557c == (FARPROC)0x0
        )))) {
      local_208 = 0xffffffff;
    }
    else {
      (*DAT_1001557c)(&local_60c,s_Second_Chance_Assertion_Failed__F_100155e4,param_2,param_3);
      OutputDebugStringA(&local_60c);
      InterlockedDecrement((LONG *)&lpAddend_10015548);
      FUN_10005e40();
      local_208 = 0xffffffff;
    }
  }
  else {
    if ((param_5 != (char *)0x0) &&
       (iVar3 = __vsnprintf(&local_408,0x1ed,param_5,local_40c), iVar3 < 0)) {
      FUN_100097a0((uint *)&local_408,(uint *)s__CrtDbgReport__String_too_long_o_100155b8);
    }
    if (param_1 == 2) {
      FUN_100097a0((uint *)&local_204,
                   (uint *)(s_Assertion_failed__100155a4 +
                           ((param_5 != (char *)0x0) - 1 & 0xffffffec)));
    }
    FUN_100097a8((uint *)&local_204,(uint *)&local_408);
    if (param_1 == 2) {
      FUN_100097a8((uint *)&local_204,(uint *)&DAT_1001558c);
    }
    if (param_2 == (undefined *)0x0) {
      FUN_100097a0((uint *)&local_60c,(uint *)&local_204);
    }
    else {
      iVar3 = __snprintf(&local_60c,0x200,s__s__d_____s_10015580,param_2,param_3,&local_204);
      if (iVar3 < 0) {
        FUN_100097a0((uint *)&local_60c,(uint *)s__CrtDbgReport__String_too_long_o_100155b8);
      }
    }
    if ((DAT_1001971c == (code *)0x0) ||
       (iVar3 = (*DAT_1001971c)(param_1,&local_60c,&local_208), iVar3 == 0)) {
      if ((((&DAT_10015550)[param_1 * 4] & 1) != 0) && (*(int *)(&DAT_10015560 + param_1 * 4) != -1)
         ) {
        lpOverlapped = (LPOVERLAPPED)0x0;
        lpNumberOfBytesWritten = &local_614;
        nNumberOfBytesToWrite = FUN_10009720((uint *)&local_60c);
        WriteFile(*(HANDLE *)(&DAT_10015560 + param_1 * 4),&local_60c,(DWORD)nNumberOfBytesToWrite,
                  lpNumberOfBytesWritten,lpOverlapped);
      }
      if (((&DAT_10015550)[param_1 * 4] & 2) != 0) {
        OutputDebugStringA(&local_60c);
      }
      if (((&DAT_10015550)[param_1 * 4] & 4) == 0) {
        if (param_1 == 2) {
          InterlockedDecrement((LONG *)&lpAddend_10015548);
        }
        local_208 = 0;
      }
      else {
        if (param_1 == 2) {
          InterlockedDecrement((LONG *)&lpAddend_10015548);
        }
        if (param_3 == 0) {
          local_62c = (char *)0x0;
        }
        else {
          local_62c = __itoa(param_3,&stack0xfffff9d8,10);
        }
        bVar1 = FUN_10006380(param_1,param_2,local_62c,param_4,&local_408);
        local_208 = CONCAT31(extraout_var,bVar1);
      }
    }
    else if (param_1 == 2) {
      InterlockedDecrement((LONG *)&lpAddend_10015548);
    }
  }
  return local_208;
}



bool __cdecl
FUN_10006380(int param_1,undefined *param_2,undefined *param_3,uint *param_4,char *param_5)

{
  uint uVar1;
  DWORD DVar2;
  char *pcVar3;
  int iVar4;
  uint *local_328;
  char *local_324;
  char *local_320;
  char *local_31c;
  char *local_318;
  uint local_314 [3];
  undefined4 uStack_308;
  uint *local_114;
  uint local_110 [65];
  int local_c;
  uint *local_8;
  
  if ((param_5 == (char *)0x0) &&
     (uVar1 = FUN_10005fc0(2,s_dbgrpt_c_1001576c,0x1d7,(uint *)0x0,s_szUserMessage____NULL_10015778)
     , uVar1 == 1)) {
    FUN_10005e40();
  }
  DVar2 = GetModuleFileNameA((HMODULE)0x0,(LPSTR)local_110,0x104);
  if (DVar2 == 0) {
    FUN_100097a0(local_110,(uint *)s_<program_name_unknown>_10015754);
  }
  local_8 = local_110;
  pcVar3 = FUN_10009720(local_8);
  if ((char *)0x40 < pcVar3) {
    pcVar3 = FUN_10009720(local_8);
    local_8 = (uint *)((int)local_8 + (int)(pcVar3 + -0x40));
    FUN_1000a1c0((char *)local_8,&DAT_10015750,3);
  }
  local_114 = param_4;
  if ((param_4 != (uint *)0x0) && (pcVar3 = FUN_10009720(param_4), (char *)0x40 < pcVar3)) {
    pcVar3 = FUN_10009720(param_4);
    local_114 = (uint *)((int)param_4 + (int)(pcVar3 + -0x40));
    FUN_1000a1c0((char *)local_114,&DAT_10015750,3);
  }
  if (*param_5 == '\0') {
    local_318 = &DAT_100156d8;
  }
  else {
    local_318 = param_5;
  }
  if ((*param_5 == '\0') || (param_1 != 2)) {
    local_31c = &DAT_100156d8;
  }
  else {
    local_31c = s_Expression__100156c8;
  }
  if (param_3 == (undefined *)0x0) {
    local_320 = &DAT_100156d8;
  }
  else {
    local_320 = param_3;
  }
  if (param_2 == (undefined *)0x0) {
    local_324 = &DAT_100156d8;
  }
  else {
    local_324 = param_2;
  }
  if (local_114 == (uint *)0x0) {
    local_328 = (uint *)&DAT_100156d8;
  }
  else {
    local_328 = local_114;
  }
  iVar4 = __snprintf((char *)local_314,0x200,s_Debug__s__Program___s_s_s_s_s_s__10015654,
                     (&PTR_s_Warning_10015570)[param_1],(char *)local_8,
                     s__Module__100156a8 + ((local_114 != (uint *)0x0) - 1 & 0x30),(char *)local_328
                     ,s__File__100156b4 + ((param_2 != (undefined *)0x0) - 1 & 0x24),local_324,
                     s__Line__100156bc + ((param_3 != (undefined *)0x0) - 1 & 0x1c),local_320,
                     &DAT_100156c4 + ((*param_5 != '\0') - 1 & 0x14),local_31c,local_318,
                     s__For_information_on_how_your_pro_100156dc + ((param_1 == 2) - 1 & 0xfffffffc)
                    );
  if (iVar4 < 0) {
    FUN_100097a0(local_314,(uint *)s__CrtDbgReport__String_too_long_o_100155b8);
  }
  uStack_308 = 0x1000665c;
  local_c = ___crtMessageBoxA((LPCSTR)local_314,s_Microsoft_Visual_C___Debug_Libra_10015630,0x12012)
  ;
  if (local_c == 3) {
    _raise(0x16);
    __exit(3);
  }
  return local_c == 4;
}



// Library Function - Single Match
//  ___InternalCxxFrameHandler
// 
// Library: Visual Studio 1998 Release

undefined4 __cdecl
___InternalCxxFrameHandler
          (int *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,int *param_5,
          int param_6,EHRegistrationNode *param_7,undefined4 param_8)

{
  undefined4 uVar1;
  
  if (*param_5 != 0x19930520) {
    FUN_1000a330();
  }
  if ((*(byte *)(param_1 + 1) & 0x66) != 0) {
    if ((param_5[1] != 0) && (param_6 == 0)) {
      ___FrameUnwindToState((int)param_2,param_4,(int)param_5,-1);
    }
    return 1;
  }
  if (param_5[3] != 0) {
    if (((*param_1 == -0x1f928c9d) && (0x19930520 < (uint)param_1[5])) &&
       (*(code **)(param_1[7] + 8) != (code *)0x0)) {
      uVar1 = (**(code **)(param_1[7] + 8))
                        (param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      return uVar1;
    }
    FindHandler((EHExceptionRecord *)param_1,param_2,param_3,param_4,(_s_FuncInfo *)param_5,
                (uchar)param_8,param_6,param_7);
  }
  return 1;
}



// Library Function - Single Match
//  void __cdecl FindHandler(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT
// *,void *,struct _s_FuncInfo const *,unsigned char,int,struct EHRegistrationNode *)
// 
// Library: Visual Studio 1998 Release

void __cdecl
FindHandler(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
           _s_FuncInfo *param_5,uchar param_6,int param_7,EHRegistrationNode *param_8)

{
  byte bVar1;
  int iVar2;
  _s_CatchableType *p_Var3;
  _ptiddata p_Var4;
  int iVar5;
  _s_HandlerType *p_Var6;
  _s_CatchableType *p_Var7;
  _s_CatchableType **pp_Var8;
  byte *pbVar9;
  int iVar10;
  byte *pbVar11;
  bool bVar12;
  int *local_18;
  uint local_c;
  uint local_8;
  uint *local_4;
  
  iVar2 = *(int *)(param_2 + 8);
  if ((iVar2 < -1) || (*(int *)(param_5 + 4) <= iVar2)) {
    FUN_1000a330();
  }
  if ((((*(int *)param_1 == -0x1f928c9d) && (*(int *)(param_1 + 0x10) == 3)) &&
      (*(int *)(param_1 + 0x14) == 0x19930520)) && (*(int *)(param_1 + 0x1c) == 0)) {
    p_Var4 = __getptd();
    if (p_Var4->ptlocinfo == (pthreadlocinfo)0x0) {
      return;
    }
    p_Var4 = __getptd();
    param_1 = (EHExceptionRecord *)p_Var4->ptlocinfo;
    p_Var4 = __getptd();
    param_3 = (_CONTEXT *)p_Var4->_ownlocale;
    iVar5 = _ValidateRead(param_1,1);
    if (iVar5 == 0) {
      FUN_1000a330();
    }
    if (((((pthreadlocinfo)param_1)->refcount == -0x1f928c9d) &&
        (((locrefcount *)((int)param_1 + 0x10))->locale == (char *)0x3)) &&
       ((((locrefcount *)((int)param_1 + 0x10))->wlocale == (wchar_t *)0x19930520 &&
        (((locrefcount *)((int)param_1 + 0x10))->wrefcount == (int *)0x0)))) {
      FUN_1000a330();
    }
  }
  if (((*(int *)param_1 == -0x1f928c9d) && (*(int *)(param_1 + 0x10) == 3)) &&
     (*(int *)(param_1 + 0x14) == 0x19930520)) {
    local_18 = (int *)FUN_10006ae0((int)param_5,param_7,iVar2,&local_c,&local_8);
    if (local_c < local_8) {
      do {
        if ((*local_18 <= iVar2) && (iVar2 <= local_18[1])) {
          p_Var6 = (_s_HandlerType *)local_18[4];
          for (iVar5 = local_18[3]; iVar5 != 0; iVar5 = iVar5 + -1) {
            pp_Var8 = *(_s_CatchableType ***)(*(int *)(param_1 + 0x1c) + 0xc);
            for (p_Var7 = *pp_Var8; p_Var7 != (_s_CatchableType *)0x0; p_Var7 = p_Var7 + -1) {
              pp_Var8 = pp_Var8 + 1;
              iVar10 = *(int *)(p_Var6 + 4);
              local_4 = *(uint **)(param_1 + 0x1c);
              p_Var3 = *pp_Var8;
              if ((iVar10 == 0) || (*(char *)(iVar10 + 8) == '\0')) {
LAB_1000691f:
                bVar12 = true;
              }
              else {
                if (iVar10 == *(int *)(p_Var3 + 4)) {
LAB_100068f9:
                  if ((((((byte)*p_Var3 & 2) == 0) || (((byte)*p_Var6 & 8) != 0)) &&
                      (((*local_4 & 1) == 0 || (((byte)*p_Var6 & 1) != 0)))) &&
                     (((*local_4 & 2) == 0 || (((byte)*p_Var6 & 2) != 0)))) goto LAB_1000691f;
                }
                else {
                  pbVar9 = (byte *)(iVar10 + 8);
                  pbVar11 = (byte *)(*(int *)(p_Var3 + 4) + 8);
                  do {
                    bVar1 = *pbVar9;
                    bVar12 = bVar1 < *pbVar11;
                    if (bVar1 != *pbVar11) {
LAB_100068f0:
                      iVar10 = (1 - (uint)bVar12) - (uint)(bVar12 != 0);
                      goto LAB_100068f5;
                    }
                    if (bVar1 == 0) break;
                    bVar1 = pbVar9[1];
                    bVar12 = bVar1 < pbVar11[1];
                    if (bVar1 != pbVar11[1]) goto LAB_100068f0;
                    pbVar9 = pbVar9 + 2;
                    pbVar11 = pbVar11 + 2;
                  } while (bVar1 != 0);
                  iVar10 = 0;
LAB_100068f5:
                  if (iVar10 == 0) goto LAB_100068f9;
                }
                bVar12 = false;
              }
              if (bVar12) {
                FUN_10006c70((pthreadlocinfo)param_1,param_2,(int)param_3,param_4,param_5,p_Var6,
                             *pp_Var8,local_18,param_7,param_8);
                goto LAB_1000697d;
              }
            }
            p_Var6 = p_Var6 + 0x10;
          }
        }
LAB_1000697d:
        local_18 = local_18 + 5;
        local_c = local_c + 1;
      } while (local_c < local_8);
    }
    if (param_6 != '\0') {
      DestructExceptionObject(param_1,'\x01');
      return;
    }
  }
  else {
    if (param_6 == '\0') {
      FUN_10006a00((pthreadlocinfo)param_1,param_2,param_3,param_4,param_5,iVar2,param_7,param_8);
      return;
    }
    FUN_1000a290();
  }
  return;
}



void __cdecl
FUN_10006a00(pthreadlocinfo param_1,EHRegistrationNode *param_2,void *param_3,void *param_4,
            _s_FuncInfo *param_5,int param_6,int param_7,EHRegistrationNode *param_8)

{
  _ptiddata p_Var1;
  int iVar2;
  int *piVar3;
  int iVar4;
  uint local_8;
  uint local_4;
  
  p_Var1 = __getptd();
  if (((p_Var1->ptmbcinfo == (pthreadmbcinfo)0x0) ||
      (iVar2 = _CallSETranslator((EHExceptionRecord *)param_1,param_2,param_3,param_4,param_5,
                                 param_7,param_8), iVar2 == 0)) &&
     (piVar3 = (int *)FUN_10006ae0((int)param_5,param_7,param_6,&local_8,&local_4),
     local_8 < local_4)) {
    do {
      if ((*piVar3 <= param_6) && (param_6 <= piVar3[1])) {
        iVar4 = piVar3[3] * 0x10 + piVar3[4];
        iVar2 = *(int *)(iVar4 + -0xc);
        if ((iVar2 == 0) || (*(char *)(iVar2 + 8) == '\0')) {
          FUN_10006c70(param_1,param_2,(int)param_3,param_4,param_5,
                       (_s_HandlerType *)(iVar4 + -0x10),(_s_CatchableType *)0x0,piVar3,param_7,
                       param_8);
        }
      }
      piVar3 = piVar3 + 5;
      local_8 = local_8 + 1;
    } while (local_8 < local_4);
  }
  return;
}



int __cdecl FUN_10006ae0(int param_1,int param_2,int param_3,uint *param_4,uint *param_5)

{
  int iVar1;
  int *piVar2;
  uint uVar3;
  uint local_c;
  uint local_8;
  
  iVar1 = *(int *)(param_1 + 0x10);
  uVar3 = *(uint *)(param_1 + 0xc);
  local_c = uVar3;
  if (-1 < param_2) {
    piVar2 = (int *)(uVar3 * 0x14 + 4 + iVar1);
    local_8 = uVar3;
    do {
      if (uVar3 == 0xffffffff) {
        FUN_1000a330();
      }
      uVar3 = uVar3 - 1;
      if (((piVar2[-5] < param_3) && (param_3 <= piVar2[-4])) || (uVar3 == 0xffffffff)) {
        param_2 = param_2 + -1;
        local_c = local_8;
        local_8 = uVar3;
      }
      piVar2 = piVar2 + -5;
    } while (-1 < param_2);
  }
  uVar3 = uVar3 + 1;
  *param_4 = uVar3;
  *param_5 = local_c;
  if ((*(uint *)(param_1 + 0xc) < local_c) || (local_c < uVar3)) {
    FUN_1000a330();
  }
  return iVar1 + uVar3 * 0x14;
}



// Library Function - Single Match
//  ___FrameUnwindToState
// 
// Library: Visual Studio 1998 Release

void __cdecl ___FrameUnwindToState(int param_1,undefined4 param_2,int param_3,int param_4)

{
  int iVar1;
  int iVar2;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_14 = *unaff_FS_OFFSET;
  puStack_c = &DAT_100130a8;
  puStack_10 = &LAB_1000a414;
  *unaff_FS_OFFSET = &local_14;
  for (iVar1 = *(int *)(param_1 + 8); iVar1 != param_4;
      iVar1 = *(int *)(*(int *)(param_3 + 8) + iVar1 * 8)) {
    local_8 = 0xffffffff;
    if ((iVar1 < 0) || (*(int *)(param_3 + 4) <= iVar1)) {
      FUN_1000a330();
    }
    local_8 = 0;
    iVar2 = *(int *)(*(int *)(param_3 + 8) + 4 + iVar1 * 8);
    if (iVar2 != 0) {
      __CallSettingFrame_12(iVar2,param_1,0x103);
    }
  }
  local_8 = 0xffffffff;
  if (iVar1 != param_4) {
    FUN_1000a330();
  }
  *(int *)(param_1 + 8) = iVar1;
  *unaff_FS_OFFSET = local_14;
  return;
}



void __cdecl
FUN_10006c70(pthreadlocinfo param_1,EHRegistrationNode *param_2,int param_3,undefined4 param_4,
            _s_FuncInfo *param_5,_s_HandlerType *param_6,_s_CatchableType *param_7,int *param_8,
            int param_9,EHRegistrationNode *param_10)

{
  void *pvVar1;
  
  if (param_7 != (_s_CatchableType *)0x0) {
    BuildCatchObject((EHExceptionRecord *)param_1,param_2,param_6,param_7);
  }
  if (param_10 == (EHRegistrationNode *)0x0) {
    param_10 = param_2;
  }
  _UnwindNestedFrames(param_10,(EHExceptionRecord *)param_1);
  ___FrameUnwindToState((int)param_2,param_4,(int)param_5,*param_8);
  *(int *)(param_2 + 8) = param_8[1] + 1;
  pvVar1 = (void *)FUN_10006d10(param_1,param_2,param_3,param_5,*(void **)(param_6 + 0xc),param_9,
                                0x100);
  if (pvVar1 != (void *)0x0) {
    _JumpToContinuation(pvVar1,param_2);
  }
  return;
}



void __cdecl
FUN_10006d10(pthreadlocinfo param_1,EHRegistrationNode *param_2,int param_3,_s_FuncInfo *param_4,
            void *param_5,int param_6,ulong param_7)

{
  pthreadlocinfo ptVar1;
  int iVar2;
  _ptiddata p_Var3;
  void *pvVar4;
  undefined4 uVar5;
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  uStack_14 = *unaff_FS_OFFSET;
  local_8 = 0xffffffff;
  puStack_c = &DAT_100130b8;
  puStack_10 = &LAB_1000a414;
  *unaff_FS_OFFSET = &uStack_14;
  uVar5 = *(undefined4 *)(param_2 + -4);
  p_Var3 = __getptd();
  ptVar1 = p_Var3->ptlocinfo;
  p_Var3 = __getptd();
  iVar2 = p_Var3->_ownlocale;
  p_Var3 = __getptd();
  p_Var3->ptlocinfo = param_1;
  p_Var3 = __getptd();
  p_Var3->_ownlocale = param_3;
  local_8 = 1;
  pvVar4 = _CallCatchBlock2(param_2,param_4,param_5,param_6,param_7);
  local_8 = 0xffffffff;
  *(undefined4 *)(param_2 + -4) = uVar5;
  p_Var3 = __getptd();
  p_Var3->ptlocinfo = ptVar1;
  p_Var3 = __getptd();
  p_Var3->_ownlocale = iVar2;
  if ((((param_1->refcount == -0x1f928c9d) && (param_1->lc_category[0].locale == (char *)0x3)) &&
      (param_1->lc_category[0].wlocale == (wchar_t *)0x19930520)) && (pvVar4 != (void *)0x0)) {
    uVar5 = FUN_10002ffa();
    DestructExceptionObject((EHExceptionRecord *)param_1,(uchar)uVar5);
  }
  return;
}



// Library Function - Single Match
//  void __cdecl BuildCatchObject(struct EHExceptionRecord *,struct EHRegistrationNode *,struct
// _s_HandlerType const *,struct _s_CatchableType const *)
// 
// Library: Visual Studio 1998 Release

void __cdecl
BuildCatchObject(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_s_HandlerType *param_3,
                _s_CatchableType *param_4)

{
  void **_Dst;
  int iVar1;
  void *pvVar2;
  undefined4 *unaff_FS_OFFSET;
  size_t _Size;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_14 = *unaff_FS_OFFSET;
  puStack_c = &DAT_100130d0;
  puStack_10 = &LAB_1000a414;
  *unaff_FS_OFFSET = &local_14;
  if (((*(int *)(param_3 + 4) != 0) && (*(char *)(*(int *)(param_3 + 4) + 8) != '\0')) &&
     (*(int *)(param_3 + 8) != 0)) {
    _Dst = (void **)(param_2 + *(int *)(param_3 + 8) + 0xc);
    local_8 = 0;
    if (((byte)*param_3 & 8) == 0) {
      if (((byte)*param_4 & 1) == 0) {
        if (*(int *)(param_4 + 0x18) == 0) {
          iVar1 = _ValidateRead(*(void **)(param_1 + 0x18),1);
          if ((iVar1 != 0) && (iVar1 = _ValidateWrite(_Dst,1), iVar1 != 0)) {
            _Size = *(size_t *)(param_4 + 0x14);
            pvVar2 = AdjustPointer(*(void **)(param_1 + 0x18),(PMD *)(param_4 + 8));
            FID_conflict__memcpy(_Dst,pvVar2,_Size);
            goto LAB_1000704e;
          }
        }
        else {
          iVar1 = _ValidateRead(*(void **)(param_1 + 0x18),1);
          if (((iVar1 != 0) && (iVar1 = _ValidateWrite(_Dst,1), iVar1 != 0)) &&
             (iVar1 = _ValidateExecute(*(_func_int **)(param_4 + 0x18)), iVar1 != 0)) {
            if (((byte)*param_4 & 4) == 0) {
              AdjustPointer(*(void **)(param_1 + 0x18),(PMD *)(param_4 + 8));
              FID_conflict__CallMemberFunction1(_Dst,*(undefined **)(param_4 + 0x18));
            }
            else {
              AdjustPointer(*(void **)(param_1 + 0x18),(PMD *)(param_4 + 8));
              FID_conflict__CallMemberFunction1(_Dst,*(undefined **)(param_4 + 0x18));
            }
            goto LAB_1000704e;
          }
        }
      }
      else {
        iVar1 = _ValidateRead(*(void **)(param_1 + 0x18),1);
        if ((iVar1 != 0) && (iVar1 = _ValidateWrite(_Dst,1), iVar1 != 0)) {
          FID_conflict__memcpy(_Dst,*(void **)(param_1 + 0x18),*(size_t *)(param_4 + 0x14));
          if ((*(int *)(param_4 + 0x14) == 4) && (*_Dst != (void *)0x0)) {
            pvVar2 = AdjustPointer(*_Dst,(PMD *)(param_4 + 8));
            *_Dst = pvVar2;
          }
          goto LAB_1000704e;
        }
      }
    }
    else {
      iVar1 = _ValidateRead(*(void **)(param_1 + 0x18),1);
      if ((iVar1 != 0) && (iVar1 = _ValidateWrite(_Dst,1), iVar1 != 0)) {
        pvVar2 = *(void **)(param_1 + 0x18);
        *_Dst = pvVar2;
        pvVar2 = AdjustPointer(pvVar2,(PMD *)(param_4 + 8));
        *_Dst = pvVar2;
        goto LAB_1000704e;
      }
    }
    FUN_1000a330();
  }
LAB_1000704e:
  *unaff_FS_OFFSET = local_14;
  return;
}



// Library Function - Single Match
//  void __cdecl DestructExceptionObject(struct EHExceptionRecord *,unsigned char)
// 
// Library: Visual Studio 1998 Release

void __cdecl DestructExceptionObject(EHExceptionRecord *param_1,uchar param_2)

{
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_14 = *unaff_FS_OFFSET;
  puStack_c = &DAT_100130e0;
  puStack_10 = &LAB_1000a414;
  *unaff_FS_OFFSET = &local_14;
  if ((param_1 != (EHExceptionRecord *)0x0) &&
     (*(void **)(*(int *)(param_1 + 0x1c) + 4) != (void *)0x0)) {
    local_8 = 0;
    _CallMemberFunction0(*(void **)(param_1 + 0x18),*(void **)(*(int *)(param_1 + 0x1c) + 4));
  }
  *unaff_FS_OFFSET = local_14;
  return;
}



// Library Function - Single Match
//  void * __cdecl AdjustPointer(void *,struct PMD const &)
// 
// Library: Visual Studio 1998 Release

void * __cdecl AdjustPointer(void *param_1,PMD *param_2)

{
  int iVar1;
  void *pvVar2;
  
  pvVar2 = (void *)(*(int *)param_2 + (int)param_1);
  iVar1 = *(int *)(param_2 + 4);
  if (-1 < iVar1) {
    pvVar2 = (void *)((int)pvVar2 +
                     iVar1 + *(int *)(*(int *)(iVar1 + (int)param_1) + *(int *)(param_2 + 8)));
  }
  return pvVar2;
}



// WARNING: Restarted to delay deadcode elimination for space: stack
// Library Function - Single Match
//  __CallSettingFrame@12
// 
// Library: Visual Studio 1998 Release

void __CallSettingFrame_12(undefined4 param_1,undefined4 param_2,int param_3)

{
  code *pcVar1;
  
  pcVar1 = (code *)FUN_1000301d(param_3);
  (*pcVar1)();
  if (param_3 == 0x100) {
    param_3 = 2;
  }
  FUN_1000301d(param_3);
  return;
}



// Library Function - Single Match
//  __mtinit
// 
// Library: Visual Studio 1998 Debug

int __cdecl __mtinit(void)

{
  _ptiddata _Ptd;
  BOOL BVar1;
  DWORD DVar2;
  pthreadlocinfo unaff_EDI;
  
  __mtinitlocks();
  DAT_10015794 = TlsAlloc();
  if (((DAT_10015794 != 0xffffffff) &&
      (_Ptd = (_ptiddata)__calloc_dbg(1,0x74,2,s_tidtable_c_10015798,99), _Ptd != (_ptiddata)0x0))
     && (BVar1 = TlsSetValue(DAT_10015794,_Ptd), BVar1 != 0)) {
    __initptd(_Ptd,unaff_EDI);
    DVar2 = GetCurrentThreadId();
    _Ptd->_tid = DVar2;
    _Ptd->_thandle = 0xffffffff;
    return 1;
  }
  return 0;
}



// Library Function - Single Match
//  __mtterm
// 
// Library: Visual Studio 1998 Debug

void __cdecl __mtterm(void)

{
  __mtdeletelocks();
  if (DAT_10015794 != 0xffffffff) {
    TlsFree(DAT_10015794);
    DAT_10015794 = 0xffffffff;
  }
  return;
}



// Library Function - Single Match
//  __initptd
// 
// Library: Visual Studio 1998 Debug

void __cdecl __initptd(_ptiddata _Ptd,pthreadlocinfo _Locale)

{
  *(undefined **)(_Ptd->_con_ch_buf + 4) = &DAT_100162b0;
  _Ptd->_holdrand = 1;
  return;
}



// Library Function - Single Match
//  __getptd
// 
// Library: Visual Studio 1998 Debug

_ptiddata __cdecl __getptd(void)

{
  DWORD dwErrCode;
  BOOL BVar1;
  DWORD DVar2;
  pthreadlocinfo unaff_EDI;
  _ptiddata local_8;
  
  dwErrCode = GetLastError();
  local_8 = (_ptiddata)TlsGetValue(DAT_10015794);
  if (local_8 == (_ptiddata)0x0) {
    local_8 = (_ptiddata)__calloc_dbg(1,0x74,2,s_tidtable_c_10015798,0xe9);
    if (local_8 != (_ptiddata)0x0) {
      BVar1 = TlsSetValue(DAT_10015794,local_8);
      if (BVar1 != 0) {
        __initptd(local_8,unaff_EDI);
        DVar2 = GetCurrentThreadId();
        local_8->_tid = DVar2;
        local_8->_thandle = 0xffffffff;
        goto LAB_100072f8;
      }
    }
    __amsg_exit(0x10);
  }
LAB_100072f8:
  SetLastError(dwErrCode);
  return local_8;
}



// Library Function - Single Match
//  __freeptd
// 
// Library: Visual Studio 1998 Debug

void __cdecl __freeptd(_ptiddata _Ptd)

{
  if (DAT_10015794 != 0xffffffff) {
    if (_Ptd == (_ptiddata)0x0) {
      _Ptd = (_ptiddata)TlsGetValue(DAT_10015794);
    }
    if (_Ptd != (_ptiddata)0x0) {
      if (_Ptd->_errmsg != (char *)0x0) {
        __free_dbg(_Ptd->_errmsg,2);
      }
      if (_Ptd->_werrmsg != (wchar_t *)0x0) {
        __free_dbg(_Ptd->_werrmsg,2);
      }
      if (_Ptd->_wnamebuf0 != (wchar_t *)0x0) {
        __free_dbg(_Ptd->_wnamebuf0,2);
      }
      if (_Ptd->_wnamebuf1 != (wchar_t *)0x0) {
        __free_dbg(_Ptd->_wnamebuf1,2);
      }
      if (_Ptd->_wasctimebuf != (wchar_t *)0x0) {
        __free_dbg(_Ptd->_wasctimebuf,2);
      }
      if (_Ptd->_gmtimebuf != (void *)0x0) {
        __free_dbg(_Ptd->_gmtimebuf,2);
      }
      __free_dbg(_Ptd,2);
    }
    TlsSetValue(DAT_10015794,(LPVOID)0x0);
  }
  return;
}



void FUN_10007420(void)

{
  GetCurrentThreadId();
  return;
}



void FUN_10007440(void)

{
  GetCurrentThread();
  return;
}



void FUN_10007460(void)

{
  DAT_10019710 = HeapCreate(0,0x1000,0);
  return;
}



void FUN_10007490(void)

{
  HeapDestroy(DAT_10019710);
  return;
}



void FUN_100074b0(void)

{
  DWORD DVar1;
  HANDLE *ppvVar2;
  HANDLE hFile;
  DWORD local_6c;
  UINT local_68;
  int local_64;
  HANDLE *local_60;
  undefined4 *local_5c;
  _STARTUPINFOA local_54;
  UINT *local_10;
  uint local_c;
  DWORD local_8;
  
  local_5c = (undefined4 *)__malloc_dbg(0x480,2,0x100157cc,0x85);
  if (local_5c == (undefined4 *)0x0) {
    __amsg_exit(0x1b);
  }
  DAT_100195d0 = 0x20;
  DAT_10019610 = local_5c;
  for (; local_5c < DAT_10019610 + 0x120; local_5c = local_5c + 9) {
    *(undefined *)(local_5c + 1) = 0;
    *local_5c = 0xffffffff;
    *(undefined *)((int)local_5c + 5) = 10;
    local_5c[2] = 0;
  }
  GetStartupInfoA(&local_54);
  if ((local_54.cbReserved2 != 0) && ((UINT *)local_54.lpReserved2 != (UINT *)0x0)) {
    local_68 = *(UINT *)local_54.lpReserved2;
    local_10 = (UINT *)((int)local_54.lpReserved2 + 4);
    local_60 = (HANDLE *)(local_68 + (int)local_10);
    if (0x7ff < (int)local_68) {
      local_68 = 0x800;
    }
    local_64 = 1;
    while ((int)DAT_100195d0 < (int)local_68) {
      local_5c = (undefined4 *)__malloc_dbg(0x480,2,0x100157cc,0xba);
      if (local_5c == (undefined4 *)0x0) {
        local_68 = DAT_100195d0;
        break;
      }
      (&DAT_10019610)[local_64] = local_5c;
      DAT_100195d0 = DAT_100195d0 + 0x20;
      for (; local_5c < (undefined4 *)((int)(&DAT_10019610)[local_64] + 0x480);
          local_5c = local_5c + 9) {
        *(undefined *)(local_5c + 1) = 0;
        *local_5c = 0xffffffff;
        *(undefined *)((int)local_5c + 5) = 10;
        local_5c[2] = 0;
      }
      local_64 = local_64 + 1;
    }
    for (local_c = 0; (int)local_c < (int)local_68; local_c = local_c + 1) {
      if (((*local_60 != (HANDLE)0xffffffff) && ((*(byte *)local_10 & 1) != 0)) &&
         (DVar1 = GetFileType(*local_60), DVar1 != 0)) {
        ppvVar2 = (HANDLE *)
                  (*(int *)((int)&DAT_10019610 + ((int)(local_c & 0xffffffe0) >> 3)) +
                  (local_c & 0x1f) * 0x24);
        *ppvVar2 = *local_60;
        *(byte *)(ppvVar2 + 1) = *(byte *)local_10;
      }
      local_10 = (UINT *)((int)local_10 + 1);
      local_60 = local_60 + 1;
    }
  }
  for (local_c = 0; (int)local_c < 3; local_c = local_c + 1) {
    ppvVar2 = (HANDLE *)(DAT_10019610 + local_c * 9);
    if (*ppvVar2 == (HANDLE)0xffffffff) {
      *(undefined *)(ppvVar2 + 1) = 0x81;
      if (local_c == 0) {
        local_6c = 0xfffffff6;
      }
      else if (local_c == 1) {
        local_6c = 0xfffffff5;
      }
      else {
        local_6c = 0xfffffff4;
      }
      hFile = GetStdHandle(local_6c);
      if ((hFile == (HANDLE)0xffffffff) || (local_8 = GetFileType(hFile), local_8 == 0)) {
        *(byte *)(ppvVar2 + 1) = *(byte *)(ppvVar2 + 1) | 0x40;
      }
      else {
        *ppvVar2 = hFile;
        if ((char)local_8 == '\x02') {
          *(byte *)(ppvVar2 + 1) = *(byte *)(ppvVar2 + 1) | 0x40;
        }
        else if ((char)local_8 == '\x03') {
          *(byte *)(ppvVar2 + 1) = *(byte *)(ppvVar2 + 1) | 8;
        }
      }
    }
    else {
      *(byte *)(ppvVar2 + 1) = *(byte *)(ppvVar2 + 1) | 0x80;
    }
  }
  SetHandleCount(DAT_100195d0);
  return;
}



// Library Function - Single Match
//  __ioterm
// 
// Library: Visual Studio 1998 Debug

void __cdecl __ioterm(void)

{
  int local_c;
  uint local_8;
  
  for (local_c = 0; local_c < 0x40; local_c = local_c + 1) {
    if ((&DAT_10019610)[local_c] != 0) {
      for (local_8 = (&DAT_10019610)[local_c]; local_8 < (&DAT_10019610)[local_c] + 0x480;
          local_8 = local_8 + 0x24) {
        if (*(int *)(local_8 + 8) != 0) {
          DeleteCriticalSection((LPCRITICAL_SECTION)(local_8 + 0xc));
        }
      }
      __free_dbg((void *)(&DAT_10019610)[local_c],2);
    }
  }
  return;
}



void FUN_100078b0(void)

{
  char *pcVar1;
  uint *puVar2;
  int local_14;
  uint **local_c;
  uint *local_8;
  
  local_14 = 0;
  for (local_8 = DAT_10014cb4; *(char *)local_8 != '\0';
      local_8 = (uint *)((int)local_8 + (int)(pcVar1 + 1))) {
    if (*(char *)local_8 != '=') {
      local_14 = local_14 + 1;
    }
    pcVar1 = FUN_10009720(local_8);
  }
  local_c = (uint **)__malloc_dbg(local_14 * 4 + 4,2,0x100157d8,0x55);
  DAT_10014d00 = local_c;
  if (local_c == (uint **)0x0) {
    __amsg_exit(9);
  }
  for (local_8 = DAT_10014cb4; *(char *)local_8 != '\0';
      local_8 = (uint *)((int)local_8 + (int)(pcVar1 + 1))) {
    pcVar1 = FUN_10009720(local_8);
    if (*(char *)local_8 != '=') {
      puVar2 = (uint *)__malloc_dbg((uint)(pcVar1 + 1),2,0x100157d8,0x61);
      *local_c = puVar2;
      if (*local_c == (uint *)0x0) {
        __amsg_exit(9);
      }
      FUN_100097a0(*local_c,local_8);
      local_c = local_c + 1;
    }
  }
  __free_dbg(DAT_10014cb4,2);
  *local_c = (uint *)0x0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __setargv
// 
// Library: Visual Studio 1998 Debug

int __cdecl __setargv(void)

{
  int local_14;
  LPSTR *local_10;
  byte **local_c;
  int local_8;
  
  GetModuleFileNameA((HMODULE)0x0,(LPSTR)&lpFilename_10018180,0x104);
  DAT_10014d10 = &lpFilename_10018180;
  if (*(char *)DAT_1001974c == '\0') {
    local_10 = &lpFilename_10018180;
  }
  else {
    local_10 = DAT_1001974c;
  }
  _parse_cmdline((byte *)local_10,(byte **)0x0,(byte *)0x0,&local_14,&local_8);
  local_c = (byte **)__malloc_dbg(local_14 * 4 + local_8,2,0x100157e4,0x79);
  if (local_c == (byte **)0x0) {
    __amsg_exit(8);
  }
  _parse_cmdline((byte *)local_10,local_c,(byte *)(local_c + local_14),&local_14,&local_8);
  _DAT_10014cf4 = local_14 + -1;
  _DAT_10014cf8 = local_c;
  return (int)local_c;
}



// Library Function - Single Match
//  _parse_cmdline
// 
// Library: Visual Studio 1998 Debug

void __cdecl _parse_cmdline(byte *param_1,byte **param_2,byte *param_3,int *param_4,int *param_5)

{
  byte *pbVar1;
  byte bVar2;
  bool bVar3;
  bool bVar4;
  uint local_18;
  byte *local_8;
  
  *param_5 = 0;
  *param_4 = 1;
  local_8 = param_1;
  if (param_2 != (byte **)0x0) {
    *param_2 = param_3;
    param_2 = param_2 + 1;
  }
  if (*param_1 == 0x22) {
    while ((pbVar1 = local_8 + 1, *pbVar1 != 0x22 && (*pbVar1 != 0))) {
      if ((((&DAT_100157f1)[*pbVar1] & 4) != 0) && (*param_5 = *param_5 + 1, param_3 != (byte *)0x0)
         ) {
        *param_3 = *pbVar1;
        param_3 = param_3 + 1;
        pbVar1 = local_8 + 2;
      }
      local_8 = pbVar1;
      *param_5 = *param_5 + 1;
      if (param_3 != (byte *)0x0) {
        *param_3 = *local_8;
        param_3 = param_3 + 1;
      }
    }
    *param_5 = *param_5 + 1;
    if (param_3 != (byte *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    if (*pbVar1 == 0x22) {
      pbVar1 = local_8 + 2;
    }
  }
  else {
    do {
      *param_5 = *param_5 + 1;
      if (param_3 != (byte *)0x0) {
        *param_3 = *local_8;
        param_3 = param_3 + 1;
      }
      bVar2 = *local_8;
      pbVar1 = local_8 + 1;
      if (((&DAT_100157f1)[bVar2] & 4) != 0) {
        *param_5 = *param_5 + 1;
        if (param_3 != (byte *)0x0) {
          *param_3 = local_8[1];
          param_3 = param_3 + 1;
        }
        pbVar1 = local_8 + 2;
      }
      local_8 = pbVar1;
    } while (((bVar2 != 0x20) && (bVar2 != 0)) && (bVar2 != 9));
    if (bVar2 == 0) {
      pbVar1 = local_8 + -1;
    }
    else {
      pbVar1 = local_8;
      if (param_3 != (byte *)0x0) {
        param_3[-1] = 0;
      }
    }
  }
  local_8 = pbVar1;
  bVar3 = false;
  while( true ) {
    if (*local_8 != 0) {
      for (; (*local_8 == 0x20 || (*local_8 == 9)); local_8 = local_8 + 1) {
      }
    }
    if (*local_8 == 0) break;
    if (param_2 != (byte **)0x0) {
      *param_2 = param_3;
      param_2 = param_2 + 1;
    }
    *param_4 = *param_4 + 1;
    while( true ) {
      bVar4 = true;
      local_18 = 0;
      for (; *local_8 == 0x5c; local_8 = local_8 + 1) {
        local_18 = local_18 + 1;
      }
      if (*local_8 == 0x22) {
        if ((local_18 & 1) == 0) {
          if (bVar3) {
            bVar4 = local_8[1] == 0x22;
            if (bVar4) {
              local_8 = local_8 + 1;
            }
          }
          else {
            bVar4 = false;
          }
          if (bVar3) {
            bVar3 = false;
          }
          else {
            bVar3 = true;
          }
        }
        local_18 = local_18 >> 1;
      }
      while (local_18 != 0) {
        if (param_3 != (byte *)0x0) {
          *param_3 = 0x5c;
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
        local_18 = local_18 - 1;
      }
      if ((*local_8 == 0) || ((!bVar3 && ((*local_8 == 0x20 || (*local_8 == 9)))))) break;
      if (bVar4) {
        if (param_3 == (byte *)0x0) {
          if (((&DAT_100157f1)[*local_8] & 4) != 0) {
            local_8 = local_8 + 1;
            *param_5 = *param_5 + 1;
          }
        }
        else {
          if (((&DAT_100157f1)[*local_8] & 4) != 0) {
            *param_3 = *local_8;
            local_8 = local_8 + 1;
            param_3 = param_3 + 1;
            *param_5 = *param_5 + 1;
          }
          *param_3 = *local_8;
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
      }
      local_8 = local_8 + 1;
    }
    if (param_3 != (byte *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    *param_5 = *param_5 + 1;
  }
  if (param_2 != (byte **)0x0) {
    *param_2 = (byte *)0x0;
  }
  *param_4 = *param_4 + 1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_10007e80(UINT param_1)

{
  UINT CodePage;
  undefined4 uVar1;
  BOOL BVar2;
  BYTE *local_2c;
  uint local_28;
  byte *local_24;
  uint local_20;
  _cpinfo local_1c;
  uint local_8;
  
  __lock(0x19);
  CodePage = _getSystemCP(param_1);
  if (DAT_100158f4 == CodePage) {
    FUN_10005cb0(0x19);
    uVar1 = 0;
  }
  else if (CodePage == 0) {
    _setSBCS();
    FUN_10005cb0(0x19);
    uVar1 = 0;
  }
  else {
    for (local_8 = 0; local_8 < 5; local_8 = local_8 + 1) {
      if (*(UINT *)(&DAT_10015918 + local_8 * 0x30) == CodePage) {
        for (local_28 = 0; local_28 < 0x101; local_28 = local_28 + 1) {
          (&DAT_100157f0)[local_28] = 0;
        }
        for (local_20 = 0; local_20 < 4; local_20 = local_20 + 1) {
          for (local_24 = &DAT_10015928 + local_8 * 0x30 + local_20 * 8;
              (*local_24 != 0 && (local_24[1] != 0)); local_24 = local_24 + 2) {
            for (local_28 = (uint)*local_24; local_28 <= local_24[1]; local_28 = local_28 + 1) {
              (&DAT_100157f1)[local_28] = (&DAT_100157f1)[local_28] | (&DAT_10015910)[local_20];
            }
          }
        }
        DAT_100158f4 = CodePage;
        _DAT_100158f8 = _CPtoLCID(CodePage);
        for (local_20 = 0; local_20 < 6; local_20 = local_20 + 1) {
          *(undefined2 *)(&DAT_10015900 + local_20 * 2) =
               *(undefined2 *)(&DAT_1001591c + local_20 * 2 + local_8 * 0x30);
        }
        FUN_10005cb0(0x19);
        return 0;
      }
    }
    BVar2 = GetCPInfo(CodePage,&local_1c);
    if (BVar2 == 1) {
      for (local_28 = 0; local_28 < 0x101; local_28 = local_28 + 1) {
        (&DAT_100157f0)[local_28] = 0;
      }
      if (local_1c.MaxCharSize < 2) {
        DAT_100158f4 = 0;
        _DAT_100158f8 = 0;
      }
      else {
        for (local_2c = local_1c.LeadByte; (*local_2c != 0 && (local_2c[1] != 0));
            local_2c = local_2c + 2) {
          for (local_28 = (uint)*local_2c; local_28 <= local_2c[1]; local_28 = local_28 + 1) {
            (&DAT_100157f1)[local_28] = (&DAT_100157f1)[local_28] | 4;
          }
        }
        for (local_28 = 1; local_28 < 0xff; local_28 = local_28 + 1) {
          (&DAT_100157f1)[local_28] = (&DAT_100157f1)[local_28] | 8;
        }
        DAT_100158f4 = CodePage;
        _DAT_100158f8 = _CPtoLCID(CodePage);
      }
      for (local_20 = 0; local_20 < 6; local_20 = local_20 + 1) {
        *(undefined2 *)(&DAT_10015900 + local_20 * 2) = 0;
      }
      FUN_10005cb0(0x19);
      uVar1 = 0;
    }
    else if (DAT_1001590c == 0) {
      FUN_10005cb0(0x19);
      uVar1 = 0xffffffff;
    }
    else {
      _setSBCS();
      FUN_10005cb0(0x19);
      uVar1 = 0;
    }
  }
  return uVar1;
}



// Library Function - Single Match
//  _getSystemCP
// 
// Library: Visual Studio 1998 Debug

UINT __cdecl _getSystemCP(UINT param_1)

{
  DAT_1001590c = 0;
  if (param_1 == 0xfffffffe) {
    DAT_1001590c = 1;
    param_1 = GetOEMCP();
  }
  else if (param_1 == 0xfffffffd) {
    DAT_1001590c = 1;
    param_1 = GetACP();
  }
  else if (param_1 == 0xfffffffc) {
    DAT_1001590c = 1;
    param_1 = DAT_10016350;
  }
  return param_1;
}



// Library Function - Single Match
//  _CPtoLCID
// 
// Library: Visual Studio 1998 Debug

undefined4 __cdecl _CPtoLCID(undefined4 param_1)

{
  undefined4 uVar1;
  
  switch(param_1) {
  case 0x3a4:
    uVar1 = 0x411;
    break;
  default:
    uVar1 = 0;
    break;
  case 0x3a8:
    uVar1 = 0x804;
    break;
  case 0x3b5:
    uVar1 = 0x412;
    break;
  case 0x3b6:
    uVar1 = 0x404;
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _setSBCS
// 
// Library: Visual Studio 1998 Debug

void _setSBCS(void)

{
  int local_8;
  
  for (local_8 = 0; local_8 < 0x101; local_8 = local_8 + 1) {
    (&DAT_100157f0)[local_8] = 0;
  }
  DAT_100158f4 = 0;
  _DAT_100158f8 = 0;
  for (local_8 = 0; local_8 < 6; local_8 = local_8 + 1) {
    *(undefined2 *)(&DAT_10015900 + local_8 * 2) = 0;
  }
  return;
}



undefined4 FUN_100083b0(void)

{
  return DAT_100158f4;
}



void FUN_100083d0(void)

{
  FUN_10007e80(0xfffffffd);
  return;
}



// Library Function - Single Match
//  ___crtGetEnvironmentStringsW
// 
// Library: Visual Studio 1998 Debug

LPVOID __cdecl ___crtGetEnvironmentStringsW(void)

{
  uint *puVar1;
  uint *in_EAX;
  uint _Size;
  int iVar2;
  char *pcVar3;
  size_t sVar4;
  uint *local_1c;
  uint *local_14;
  int local_10;
  uint *local_8;
  
  local_8 = (uint *)0x0;
  local_10 = 0;
  if (DAT_10015a08 == 0) {
    in_EAX = (uint *)GetEnvironmentStringsW();
    if (in_EAX == (uint *)0x0) {
      in_EAX = (uint *)GetEnvironmentStrings();
      if (in_EAX == (uint *)0x0) {
        return (LPVOID)0x0;
      }
      DAT_10015a08 = 2;
      local_8 = in_EAX;
    }
    else {
      DAT_10015a08 = 1;
      local_8 = in_EAX;
    }
  }
  if (DAT_10015a08 == 1) {
    if ((local_8 == (uint *)0x0) &&
       (local_8 = (uint *)GetEnvironmentStringsW(), local_8 == (uint *)0x0)) {
      in_EAX = (uint *)0x0;
    }
    else {
      local_14 = local_8;
      puVar1 = local_14;
      while (local_14 = puVar1, *(short *)local_14 != 0) {
        puVar1 = (uint *)((int)local_14 + 2);
        if (*(short *)(uint *)((int)local_14 + 2) == 0) {
          puVar1 = local_14 + 1;
        }
      }
      _Size = (int)local_14 + (2 - (int)local_8);
      in_EAX = (uint *)__malloc_dbg(_Size,2,0x10015a10,0x57);
      if (in_EAX == (uint *)0x0) {
        FreeEnvironmentStringsW((LPWCH)local_8);
        in_EAX = (uint *)0x0;
      }
      else {
        FID_conflict__memcpy(in_EAX,local_8,_Size);
        FreeEnvironmentStringsW((LPWCH)local_8);
      }
    }
  }
  else if (DAT_10015a08 == 2) {
    if ((local_8 == (uint *)0x0) &&
       (local_8 = (uint *)GetEnvironmentStrings(), local_8 == (uint *)0x0)) {
      in_EAX = (uint *)0x0;
    }
    else {
      for (local_1c = local_8; *(char *)local_1c != '\0';
          local_1c = (uint *)((int)local_1c + (int)(pcVar3 + 1))) {
        iVar2 = MultiByteToWideChar(DAT_10016350,1,(LPCSTR)local_1c,-1,(LPWSTR)0x0,0);
        if (iVar2 == 0) {
          return (LPVOID)0x0;
        }
        local_10 = local_10 + iVar2;
        pcVar3 = FUN_10009720(local_1c);
      }
      in_EAX = (uint *)__malloc_dbg((local_10 + 1) * 2,2,0x10015a10,0x87);
      if (in_EAX == (uint *)0x0) {
        FreeEnvironmentStringsA((LPCH)local_8);
        in_EAX = (uint *)0x0;
      }
      else {
        local_1c = local_8;
        local_14 = in_EAX;
        while (*(char *)local_1c != '\0') {
          iVar2 = MultiByteToWideChar(DAT_10016350,1,(LPCSTR)local_1c,-1,(LPWSTR)local_14,
                                      (local_10 + 1) - ((int)local_14 - (int)in_EAX >> 1));
          if (iVar2 == 0) {
            __free_dbg(in_EAX,2);
            FreeEnvironmentStringsA((LPCH)local_8);
            return (LPVOID)0x0;
          }
          pcVar3 = FUN_10009720(local_1c);
          local_1c = (uint *)((int)local_1c + (int)(pcVar3 + 1));
          sVar4 = _wcslen((wchar_t *)local_14);
          local_14 = (uint *)((int)local_14 + sVar4 * 2 + 2);
        }
        *(undefined2 *)local_14 = 0;
        FreeEnvironmentStringsA((LPCH)local_8);
      }
    }
  }
  return in_EAX;
}



LPSTR FUN_100086b0(void)

{
  char *pcVar1;
  LPWCH pWVar2;
  int iVar3;
  uint cbMultiByte;
  LPSTR _Dst;
  LPWCH local_1c;
  char *local_18;
  LPSTR local_14;
  LPWCH local_c;
  
  if (DAT_10015a0c == 0) {
    local_1c = GetEnvironmentStringsW();
    if (local_1c == (LPWCH)0x0) {
      local_14 = GetEnvironmentStrings();
      if (local_14 == (LPCH)0x0) {
        return (LPSTR)0x0;
      }
      DAT_10015a0c = 2;
    }
    else {
      DAT_10015a0c = 1;
    }
  }
  if (DAT_10015a0c == 1) {
    if ((local_1c == (LPWCH)0x0) && (local_1c = GetEnvironmentStringsW(), local_1c == (LPWCH)0x0)) {
      _Dst = (LPSTR)0x0;
    }
    else {
      local_c = local_1c;
      pWVar2 = local_c;
      while (local_c = pWVar2, *local_c != L'\0') {
        pWVar2 = local_c + 1;
        if (local_c[1] == L'\0') {
          pWVar2 = local_c + 2;
        }
      }
      iVar3 = ((int)local_c - (int)local_1c >> 1) + 1;
      cbMultiByte = WideCharToMultiByte(0,0,local_1c,iVar3,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0);
      if ((cbMultiByte == 0) ||
         (local_14 = (LPSTR)__malloc_dbg(cbMultiByte,2,0x10015a10,0xfb), local_14 == (LPSTR)0x0)) {
        FreeEnvironmentStringsW(local_1c);
        _Dst = (LPSTR)0x0;
      }
      else {
        iVar3 = WideCharToMultiByte(0,0,local_1c,iVar3,local_14,cbMultiByte,(LPCSTR)0x0,(LPBOOL)0x0)
        ;
        if (iVar3 == 0) {
          __free_dbg(local_14,2);
          local_14 = (LPSTR)0x0;
        }
        FreeEnvironmentStringsW(local_1c);
        _Dst = local_14;
      }
    }
  }
  else if (DAT_10015a0c == 2) {
    if ((local_14 == (LPCH)0x0) && (local_14 = GetEnvironmentStrings(), local_14 == (LPCH)0x0)) {
      _Dst = (LPSTR)0x0;
    }
    else {
      local_18 = local_14;
      pcVar1 = local_18;
      while (local_18 = pcVar1, *local_18 != '\0') {
        pcVar1 = local_18 + 1;
        if (local_18[1] == '\0') {
          pcVar1 = local_18 + 2;
        }
      }
      _Dst = (LPSTR)__malloc_dbg((uint)(local_18 + (1 - (int)local_14)),2,0x10015a10,0x126);
      if (_Dst == (LPSTR)0x0) {
        FreeEnvironmentStringsA(local_14);
        _Dst = (LPSTR)0x0;
      }
      else {
        FID_conflict__memcpy(_Dst,local_14,(size_t)(local_18 + (1 - (int)local_14)));
        FreeEnvironmentStringsA(local_14);
      }
    }
  }
  else {
    _Dst = (LPSTR)0x0;
  }
  return _Dst;
}



// Library Function - Single Match
//  __set_error_mode
// 
// Library: Visual Studio 1998 Debug

int __cdecl __set_error_mode(int _Mode)

{
  int iVar1;
  
  if (-1 < _Mode) {
    if (_Mode < 3) {
      iVar1 = DAT_10014cc0;
      DAT_10014cc0 = _Mode;
      return iVar1;
    }
    if (_Mode == 3) {
      return DAT_10014cc0;
    }
  }
  return -1;
}



void __cdecl FUN_10008980(undefined4 param_1)

{
  DAT_10014cc4 = param_1;
  return;
}



// Library Function - Single Match
//  __FF_MSGBANNER
// 
// Library: Visual Studio 1998 Debug

void __cdecl __FF_MSGBANNER(void)

{
  if ((DAT_10014cc0 == 1) || ((DAT_10014cc0 == 0 && (DAT_10014cc4 == 1)))) {
    FUN_10008a00(0xfc);
    if (DAT_10015d08 != (code *)0x0) {
      (*DAT_10015d08)();
    }
    FUN_10008a00(0xff);
  }
  return;
}



void __cdecl FUN_10008a00(int param_1)

{
  code *pcVar1;
  uint uVar2;
  char *pcVar3;
  DWORD DVar4;
  DWORD *lpNumberOfBytesWritten;
  LPOVERLAPPED lpOverlapped;
  HANDLE local_1b8;
  uint local_1b4 [65];
  uint *local_b0;
  uint local_ac [40];
  uint local_c;
  DWORD local_8;
  
  for (local_c = 0; (local_c < 0x11 && (*(int *)(&DAT_10015c80 + local_c * 8) != param_1));
      local_c = local_c + 1) {
  }
  if (*(int *)(&DAT_10015c80 + local_c * 8) == param_1) {
    if ((param_1 != 0xfc) &&
       (uVar2 = FUN_10005fc0(1,(undefined *)0x0,0,(uint *)0x0,
                             (&PTR_s_R6002___floating_point_not_loade_10015c84)[local_c * 2]),
       uVar2 == 1)) {
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    if ((DAT_10014cc0 == 1) || ((DAT_10014cc0 == 0 && (DAT_10014cc4 == 1)))) {
      if (*(int *)(DAT_10019610 + 0x48) == -1) {
        local_1b8 = GetStdHandle(0xfffffff4);
      }
      else {
        local_1b8 = *(HANDLE *)(DAT_10019610 + 0x48);
      }
      lpOverlapped = (LPOVERLAPPED)0x0;
      lpNumberOfBytesWritten = &local_8;
      pcVar3 = FUN_10009720((uint *)(&PTR_s_R6002___floating_point_not_loade_10015c84)[local_c * 2])
      ;
      WriteFile(local_1b8,(&PTR_s_R6002___floating_point_not_loade_10015c84)[local_c * 2],
                (DWORD)pcVar3,lpNumberOfBytesWritten,lpOverlapped);
    }
    else if (param_1 != 0xfc) {
      DVar4 = GetModuleFileNameA((HMODULE)0x0,(LPSTR)local_1b4,0x104);
      if (DVar4 == 0) {
        FUN_100097a0(local_1b4,(uint *)s_<program_name_unknown>_10015754);
      }
      local_b0 = local_1b4;
      pcVar3 = FUN_10009720(local_b0);
      if ((char *)0x3c < pcVar3 + 1) {
        pcVar3 = FUN_10009720(local_1b4);
        local_b0 = (uint *)((int)local_b0 + (int)(pcVar3 + -0x3b));
        FUN_1000a1c0((char *)local_b0,&DAT_10015750,3);
      }
      FUN_100097a0(local_ac,(uint *)s_Runtime_Error__Program__10015d34);
      FUN_100097a8(local_ac,local_b0);
      FUN_100097a8(local_ac,(uint *)&DAT_100156c4);
      FUN_100097a8(local_ac,(uint *)(&PTR_s_R6002___floating_point_not_loade_10015c84)[local_c * 2])
      ;
      ___crtMessageBoxA((LPCSTR)local_ac,s_Microsoft_Visual_C___Runtime_Lib_10015d0c,0x12010);
    }
  }
  return;
}



// Library Function - Single Match
//  __GET_RTERRMSG
// 
// Library: Visual Studio 1998 Debug

wchar_t * __cdecl __GET_RTERRMSG(int param_1)

{
  wchar_t *pwVar1;
  uint local_8;
  
  for (local_8 = 0; (local_8 < 0x11 && (*(int *)(&DAT_10015c80 + local_8 * 8) != param_1));
      local_8 = local_8 + 1) {
  }
  if (*(int *)(&DAT_10015c80 + local_8 * 8) == param_1) {
    pwVar1 = (wchar_t *)(&PTR_s_R6002___floating_point_not_loade_10015c84)[local_8 * 2];
  }
  else {
    pwVar1 = (wchar_t *)0x0;
  }
  return pwVar1;
}



// Library Function - Single Match
//  int (__cdecl*__cdecl _set_new_handler(int (__cdecl*)(unsigned int)))(unsigned int)
// 
// Library: Visual Studio 1998 Debug

_func_int_uint * __cdecl _set_new_handler(_func_int_uint *param_1)

{
  _func_int_uint *p_Var1;
  
  __lock(9);
  p_Var1 = DAT_10018284;
  DAT_10018284 = param_1;
  FUN_10005cb0(9);
  return p_Var1;
}



undefined4 FUN_10008ce0(void)

{
  return DAT_10018284;
}



// Library Function - Single Match
//  void (__cdecl*__cdecl set_new_handler(void (__cdecl*)(void)))(void)
// 
// Library: Visual Studio 1998 Debug

_func_void * __cdecl set_new_handler(_func_void *param_1)

{
  if (param_1 != (_func_void *)0x0) {
    FUN_1000aa50((uint *)s_new_p____0_10015d54,(uint *)s_handler_cpp_10015d60,0x72);
  }
  _set_new_handler((_func_int_uint *)0x0);
  return (_func_void *)0x0;
}



// Library Function - Single Match
//  __callnewh
// 
// Library: Visual Studio 1998 Debug

int __cdecl __callnewh(size_t _Size)

{
  int iVar1;
  
  __lock(9);
  if ((DAT_10018284 != (code *)0x0) && (iVar1 = (*DAT_10018284)(_Size), iVar1 != 0)) {
    FUN_10005cb0(9);
    return 1;
  }
  FUN_10005cb0(9);
  return 0;
}



// Library Function - Single Match
//  __malloc_base
// 
// Library: Visual Studio 1998 Debug

void __cdecl __malloc_base(uint param_1)

{
  FUN_10008de0(param_1,DAT_10015d50);
  return;
}



int __cdecl FUN_10008de0(uint param_1,int param_2)

{
  int iVar1;
  
  if (param_1 < 0xffffffe1) {
    if (param_1 == 0) {
      param_1 = 1;
    }
    do {
      iVar1 = FUN_10008e60(param_1);
      if (iVar1 != 0) {
        return iVar1;
      }
      if (param_2 == 0) {
        return 0;
      }
      iVar1 = __callnewh(param_1);
    } while (iVar1 != 0);
  }
  return 0;
}



void __cdecl FUN_10008e60(SIZE_T param_1)

{
  HeapAlloc(DAT_10019710,0,param_1);
  return;
}



undefined4 FUN_10008e90(void)

{
  return 1;
}



void __cdecl FUN_10008eb0(LPVOID param_1,uint param_2)

{
  if (param_2 == 0) {
    param_2 = 1;
  }
  if (0xffffffe0 < param_2) {
    param_2 = 0xffffffe0;
  }
  HeapReAlloc(DAT_10019710,0x10,param_1,param_2);
  return;
}



LPVOID __cdecl FUN_10008f00(LPVOID param_1,uint param_2)

{
  LPVOID pvVar1;
  int iVar2;
  LPVOID local_8;
  
  if (param_1 == (LPVOID)0x0) {
    pvVar1 = (LPVOID)__malloc_base(param_2);
  }
  else if (param_2 == 0) {
    FUN_10008fc0(param_1);
    pvVar1 = (LPVOID)0x0;
  }
  else {
    do {
      if (param_2 < 0xffffffe1) {
        local_8 = HeapReAlloc(DAT_10019710,0,param_1,param_2);
      }
      else {
        local_8 = (LPVOID)0x0;
      }
      if (local_8 != (LPVOID)0x0) {
        return local_8;
      }
      if (DAT_10015d50 == 0) {
        return (LPVOID)0x0;
      }
      iVar2 = __callnewh(param_2);
    } while (iVar2 != 0);
    pvVar1 = (LPVOID)0x0;
  }
  return pvVar1;
}



void __cdecl FUN_10008fc0(LPVOID param_1)

{
  if (param_1 != (LPVOID)0x0) {
    HeapFree(DAT_10019710,0,param_1);
  }
  return;
}



undefined4 FUN_10008ff0(void)

{
  BOOL BVar1;
  DWORD DVar2;
  ulong *puVar3;
  int *piVar4;
  
  BVar1 = HeapValidate(DAT_10019710,0,(LPCVOID)0x0);
  if (BVar1 == 0) {
    DVar2 = GetLastError();
    if (DVar2 != 0x78) {
      return 0xfffffffc;
    }
    puVar3 = FUN_1000aef0();
    *puVar3 = 0x78;
    piVar4 = FUN_1000aed0();
    *piVar4 = 0x28;
  }
  return 0xfffffffe;
}



DWORD __cdecl FUN_10009060(int param_1)

{
  BOOL BVar1;
  DWORD DVar2;
  ulong *puVar3;
  int *piVar4;
  undefined4 *unaff_FS_OFFSET;
  _PROCESS_HEAP_ENTRY local_38;
  undefined *local_1c;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_100130f0;
  puStack_10 = &LAB_1000a414;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  local_1c = &stack0xffffffb0;
  BVar1 = HeapValidate(DAT_10019710,0,(LPCVOID)0x0);
  if (BVar1 == 0) {
    DVar2 = GetLastError();
    if (DVar2 == 0x78) {
      puVar3 = FUN_1000aef0();
      *puVar3 = 0x78;
      piVar4 = FUN_1000aed0();
      *piVar4 = 0x28;
      DVar2 = 0xfffffffe;
    }
    else {
      DVar2 = 0xfffffffc;
    }
LAB_10009214:
    *unaff_FS_OFFSET = local_14;
    return DVar2;
  }
  if ((DAT_10015d70 == 0) && (BVar1 = HeapLock(DAT_10019710), BVar1 == 0)) {
    DVar2 = GetLastError();
    if (DVar2 != 0x78) {
      DVar2 = 0xfffffffd;
      goto LAB_10009214;
    }
    DAT_10015d70 = DAT_10015d70 + 1;
  }
  local_38.lpData = (void *)0x0;
  local_8 = 0;
  while (BVar1 = HeapWalk(DAT_10019710,&local_38), BVar1 != 0) {
    if (((local_38.wFlags & 3) == 0) && ((local_38.wFlags & 4) == 0)) {
      local_8 = 1;
      _memset(local_38.lpData,param_1,local_38.cbData);
      local_8 = 0;
    }
  }
  DVar2 = GetLastError();
  local_8 = 0xffffffff;
  if (DAT_10015d70 == 0) {
    DVar2 = HeapUnlock(DAT_10019710);
  }
  return DVar2;
}



// Library Function - Single Match
//  _sprintf
// 
// Library: Visual Studio 1998 Debug

int __cdecl _sprintf(char *_Dest,char *_Format,...)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  FILE local_28;
  int local_8;
  
  if (_Dest == (char *)0x0) {
    uVar2 = FUN_10005fc0(2,s_sprintf_c_10015d84,0x5d,(uint *)0x0,s_string____NULL_10015d90);
    if (uVar2 == 1) {
      pcVar1 = (code *)swi(3);
      iVar3 = (*pcVar1)();
      return iVar3;
    }
  }
  if (_Format == (char *)0x0) {
    uVar2 = FUN_10005fc0(2,s_sprintf_c_10015d84,0x5e,(uint *)0x0,s_format____NULL_10015d74);
    if (uVar2 == 1) {
      pcVar1 = (code *)swi(3);
      iVar3 = (*pcVar1)();
      return iVar3;
    }
  }
  local_28._flag = 0x42;
  local_28._base = _Dest;
  local_28._ptr = _Dest;
  local_28._cnt = 0x7fffffff;
  local_8 = FUN_1000b1b0(&local_28,(byte *)_Format,(undefined4 *)&stack0x0000000c);
  local_28._cnt = local_28._cnt + -1;
  if (local_28._cnt < 0) {
    __flsbuf(0,&local_28);
  }
  else {
    *local_28._ptr = '\0';
  }
  return local_8;
}



// Library Function - Single Match
//  __isctype
// 
// Library: Visual Studio 1998 Debug

int __cdecl __isctype(int _C,int _Type)

{
  BOOL BVar1;
  uint uVar2;
  BOOL unaff_EDI;
  LPCSTR local_10;
  uint local_c;
  undefined local_8;
  undefined local_7;
  undefined local_6;
  
  if (_C + 1U < 0x101) {
    uVar2 = (uint)*(ushort *)(PTR_DAT_10015da0 + _C * 2) & _Type;
  }
  else {
    if ((*(ushort *)(PTR_DAT_10015da0 + ((uint)_C >> 8 & 0xff) * 2) & 0x8000) == 0) {
      local_8 = (undefined)_C;
      local_7 = 0;
      local_10 = (LPCSTR)0x1;
    }
    else {
      local_8 = (undefined)((uint)_C >> 8);
      local_7 = (undefined)_C;
      local_6 = 0;
      local_10 = (LPCSTR)0x2;
    }
    BVar1 = ___crtGetStringTypeA
                      ((_locale_t)0x1,(DWORD)&local_8,local_10,(int)&local_c,(LPWORD)0x0,0,unaff_EDI
                      );
    if (BVar1 == 0) {
      uVar2 = 0;
    }
    else {
      uVar2 = local_c & 0xffff & _Type;
    }
  }
  return uVar2;
}



// Library Function - Single Match
//  ___initstdio
// 
// Library: Visual Studio 1998 Debug

void ___initstdio(void)

{
  uint local_8;
  
  if (DAT_1001828c == 0) {
    DAT_1001828c = 0x200;
  }
  else if (DAT_1001828c < 0x14) {
    DAT_1001828c = 0x14;
  }
  DAT_100185cc = __calloc_dbg(DAT_1001828c,4,2,s__file_c_1001623c,0x86);
  if (DAT_100185cc == (undefined *)0x0) {
    DAT_1001828c = 0x14;
    DAT_100185cc = __calloc_dbg(0x14,4,2,s__file_c_1001623c,0x89);
    if (DAT_100185cc == (undefined *)0x0) {
      __amsg_exit(0x1a);
    }
  }
  for (local_8 = 0; (int)local_8 < 0x14; local_8 = local_8 + 1) {
    *(undefined ***)(DAT_100185cc + local_8 * 4) = &PTR_DAT_10015fb8 + local_8 * 8;
  }
  for (local_8 = 0; (int)local_8 < 3; local_8 = local_8 + 1) {
    if ((*(int *)(*(int *)((int)&DAT_10019610 + ((int)(local_8 & 0xffffffe0) >> 3)) +
                 (local_8 & 0x1f) * 0x24) == -1) ||
       (*(int *)(*(int *)((int)&DAT_10019610 + ((int)(local_8 & 0xffffffe0) >> 3)) +
                (local_8 & 0x1f) * 0x24) == 0)) {
      *(undefined4 *)(&DAT_10015fc8 + local_8 * 0x20) = 0xffffffff;
    }
  }
  return;
}



// Library Function - Single Match
//  ___endstdio
// 
// Library: Visual Studio 1998 Debug

void ___endstdio(void)

{
  __flushall();
  if (DAT_10014d18 != '\0') {
    FUN_1000c670();
  }
  return;
}



// Library Function - Single Match
//  __itoa
// 
// Library: Visual Studio 1998 Debug

char * __cdecl __itoa(int _Value,char *_Dest,int _Radix)

{
  if ((_Radix == 10) && (_Value < 0)) {
    _xtoa(_Value,_Dest,10,1);
  }
  else {
    _xtoa(_Value,_Dest,_Radix,0);
  }
  return _Dest;
}



// Library Function - Single Match
//  _xtoa
// 
// Library: Visual Studio 1998 Debug

void __cdecl _xtoa(uint param_1,char *param_2,uint param_3,int param_4)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  char *local_c;
  char *local_8;
  
  local_8 = param_2;
  if (param_4 != 0) {
    *param_2 = '-';
    local_8 = param_2 + 1;
    param_1 = -param_1;
  }
  local_c = local_8;
  do {
    pcVar2 = local_8;
    uVar3 = param_1 % param_3;
    param_1 = param_1 / param_3;
    cVar1 = (char)uVar3;
    if (uVar3 < 10) {
      *local_8 = cVar1 + '0';
    }
    else {
      *local_8 = cVar1 + 'W';
    }
    local_8 = local_8 + 1;
  } while (param_1 != 0);
  *local_8 = '\0';
  local_8 = pcVar2;
  do {
    cVar1 = *local_8;
    *local_8 = *local_c;
    *local_c = cVar1;
    local_8 = local_8 + -1;
    local_c = local_c + 1;
  } while (local_c < local_8);
  return;
}



// Library Function - Single Match
//  __ltoa
// 
// Library: Visual Studio 1998 Debug

char * __cdecl __ltoa(long _Value,char *_Dest,int _Radix)

{
  int local_8;
  
  if ((_Radix == 10) && (_Value < 0)) {
    local_8 = 1;
  }
  else {
    local_8 = 0;
  }
  _xtoa(_Value,_Dest,_Radix,local_8);
  return _Dest;
}



// Library Function - Single Match
//  __ultoa
// 
// Library: Visual Studio 1998 Debug

char * __cdecl __ultoa(ulong _Value,char *_Dest,int _Radix)

{
  _xtoa(_Value,_Dest,_Radix,0);
  return _Dest;
}



char * __cdecl FUN_10009720(uint *param_1)

{
  char cVar1;
  uint uVar2;
  uint *puVar3;
  uint *puVar4;
  bool bVar5;
  
  uVar2 = (uint)param_1 & 3;
  puVar3 = param_1;
  while (uVar2 != 0) {
    cVar1 = *(char *)puVar3;
    puVar3 = (uint *)((int)puVar3 + 1);
    if (cVar1 == '\0') goto LAB_1000976f;
    uVar2 = (uint)puVar3 & 3;
  }
  do {
    do {
      puVar4 = puVar3;
      puVar3 = puVar4 + 1;
    } while (((*puVar4 ^ 0xffffffff ^ *puVar4 + 0x7efefeff) & 0x81010100) == 0);
    uVar2 = *puVar4;
    if ((char)uVar2 == '\0') {
      return (char *)((int)puVar4 - (int)param_1);
    }
    if ((char)(uVar2 >> 8) == '\0') {
      return (char *)((int)puVar4 + (1 - (int)param_1));
    }
    if ((uVar2 & 0xff0000) == 0) {
      return (char *)((int)puVar4 + (2 - (int)param_1));
    }
    bVar5 = (uVar2 & 0xff000000) != 0;
  } while ((bVar5) && (bVar5));
LAB_1000976f:
  return (char *)((int)puVar3 + (-1 - (int)param_1));
}



uint * __cdecl FUN_100097a0(uint *param_1,uint *param_2)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  
  uVar3 = (uint)param_2 & 3;
  puVar4 = param_1;
  while (uVar3 != 0) {
    bVar1 = *(byte *)param_2;
    uVar3 = (uint)bVar1;
    param_2 = (uint *)((int)param_2 + 1);
    if (bVar1 == 0) goto LAB_10009880;
    *(byte *)puVar4 = bVar1;
    puVar4 = (uint *)((int)puVar4 + 1);
    uVar3 = (uint)param_2 & 3;
  }
  do {
    uVar2 = *param_2;
    uVar3 = *param_2;
    param_2 = param_2 + 1;
    if (((uVar2 ^ 0xffffffff ^ uVar2 + 0x7efefeff) & 0x81010100) != 0) {
      if ((char)uVar3 == '\0') {
LAB_10009880:
        *(byte *)puVar4 = (byte)uVar3;
        return param_1;
      }
      if ((char)(uVar3 >> 8) == '\0') {
        *(short *)puVar4 = (short)uVar3;
        return param_1;
      }
      if ((uVar3 & 0xff0000) == 0) {
        *(short *)puVar4 = (short)uVar3;
        *(byte *)((int)puVar4 + 2) = 0;
        return param_1;
      }
      if ((uVar3 & 0xff000000) == 0) {
        *puVar4 = uVar3;
        return param_1;
      }
    }
    *puVar4 = uVar3;
    puVar4 = puVar4 + 1;
  } while( true );
}



uint * __cdecl FUN_100097a8(uint *param_1,uint *param_2)

{
  byte bVar1;
  uint uVar2;
  uint *puVar3;
  uint uVar4;
  uint *puVar5;
  
  uVar4 = (uint)param_1 & 3;
  puVar3 = param_1;
  while (uVar4 != 0) {
    bVar1 = *(byte *)puVar3;
    puVar3 = (uint *)((int)puVar3 + 1);
    if (bVar1 == 0) goto LAB_100097f7;
    uVar4 = (uint)puVar3 & 3;
  }
  do {
    do {
      puVar5 = puVar3;
      puVar3 = puVar5 + 1;
    } while (((*puVar5 ^ 0xffffffff ^ *puVar5 + 0x7efefeff) & 0x81010100) == 0);
    uVar4 = *puVar5;
    if ((char)uVar4 == '\0') goto LAB_10009809;
    if ((char)(uVar4 >> 8) == '\0') {
      puVar5 = (uint *)((int)puVar5 + 1);
      goto LAB_10009809;
    }
    if ((uVar4 & 0xff0000) == 0) {
      puVar5 = (uint *)((int)puVar5 + 2);
      goto LAB_10009809;
    }
  } while ((uVar4 & 0xff000000) != 0);
LAB_100097f7:
  puVar5 = (uint *)((int)puVar3 + -1);
LAB_10009809:
  uVar4 = (uint)param_2 & 3;
  while (uVar4 != 0) {
    bVar1 = *(byte *)param_2;
    uVar4 = (uint)bVar1;
    param_2 = (uint *)((int)param_2 + 1);
    if (bVar1 == 0) goto LAB_10009880;
    *(byte *)puVar5 = bVar1;
    puVar5 = (uint *)((int)puVar5 + 1);
    uVar4 = (uint)param_2 & 3;
  }
  do {
    uVar2 = *param_2;
    uVar4 = *param_2;
    param_2 = param_2 + 1;
    if (((uVar2 ^ 0xffffffff ^ uVar2 + 0x7efefeff) & 0x81010100) != 0) {
      if ((char)uVar4 == '\0') {
LAB_10009880:
        *(byte *)puVar5 = (byte)uVar4;
        return param_1;
      }
      if ((char)(uVar4 >> 8) == '\0') {
        *(short *)puVar5 = (short)uVar4;
        return param_1;
      }
      if ((uVar4 & 0xff0000) == 0) {
        *(short *)puVar5 = (short)uVar4;
        *(byte *)((int)puVar5 + 2) = 0;
        return param_1;
      }
      if ((uVar4 & 0xff000000) == 0) {
        *puVar5 = uVar4;
        return param_1;
      }
    }
    *puVar5 = uVar4;
    puVar5 = puVar5 + 1;
  } while( true );
}



// Library Function - Single Match
//  __snprintf
// 
// Library: Visual Studio 1998 Debug

int __cdecl __snprintf(char *_Dest,size_t _Count,char *_Format,...)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  FILE local_28;
  int local_8;
  
  if (_Dest == (char *)0x0) {
    uVar2 = FUN_10005fc0(2,s_sprintf_c_10015d84,0x5d,(uint *)0x0,s_string____NULL_10015d90);
    if (uVar2 == 1) {
      pcVar1 = (code *)swi(3);
      iVar3 = (*pcVar1)();
      return iVar3;
    }
  }
  if (_Format == (char *)0x0) {
    uVar2 = FUN_10005fc0(2,s_sprintf_c_10015d84,0x5e,(uint *)0x0,s_format____NULL_10015d74);
    if (uVar2 == 1) {
      pcVar1 = (code *)swi(3);
      iVar3 = (*pcVar1)();
      return iVar3;
    }
  }
  local_28._flag = 0x42;
  local_28._base = _Dest;
  local_28._ptr = _Dest;
  local_28._cnt = _Count;
  local_8 = FUN_1000b1b0(&local_28,(byte *)_Format,(undefined4 *)&stack0x00000010);
  local_28._cnt = local_28._cnt - 1;
  if (local_28._cnt < 0) {
    __flsbuf(0,&local_28);
  }
  else {
    *local_28._ptr = '\0';
  }
  return local_8;
}



// Library Function - Single Match
//  __vsnprintf
// 
// Library: Visual Studio 1998 Debug

int __cdecl __vsnprintf(char *_Dest,size_t _Count,char *_Format,va_list _Args)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  FILE local_28;
  int local_8;
  
  if (_Dest == (char *)0x0) {
    uVar2 = FUN_10005fc0(2,s_vsprintf_c_10016244,0x5a,(uint *)0x0,s_string____NULL_10015d90);
    if (uVar2 == 1) {
      pcVar1 = (code *)swi(3);
      iVar3 = (*pcVar1)();
      return iVar3;
    }
  }
  if (_Format == (char *)0x0) {
    uVar2 = FUN_10005fc0(2,s_vsprintf_c_10016244,0x5b,(uint *)0x0,s_format____NULL_10015d74);
    if (uVar2 == 1) {
      pcVar1 = (code *)swi(3);
      iVar3 = (*pcVar1)();
      return iVar3;
    }
  }
  local_28._flag = 0x42;
  local_28._base = _Dest;
  local_28._ptr = _Dest;
  local_28._cnt = _Count;
  local_8 = FUN_1000b1b0(&local_28,(byte *)_Format,(undefined4 *)_Args);
  local_28._cnt = local_28._cnt - 1;
  if (local_28._cnt < 0) {
    __flsbuf(0,&local_28);
  }
  else {
    *local_28._ptr = '\0';
  }
  return local_8;
}



// Library Function - Single Match
//  _signal
// 
// Library: Visual Studio 1998 Debug

void __cdecl _signal(int param_1)

{
  BOOL BVar1;
  ulong *puVar2;
  DWORD DVar3;
  _ptiddata p_Var4;
  undefined4 uVar5;
  int *piVar6;
  int in_stack_00000008;
  uint local_c;
  
  if ((in_stack_00000008 != 4) && (in_stack_00000008 != 3)) {
    if ((param_1 == 2) || (((param_1 == 0x15 || (param_1 == 0x16)) || (param_1 == 0xf)))) {
      __lock(1);
      if (((param_1 == 2) || (param_1 == 0x15)) && (DAT_10016260 == 0)) {
        BVar1 = SetConsoleCtrlHandler(_ctrlevent_capture_4,1);
        if (BVar1 != 1) {
          puVar2 = FUN_1000aef0();
          DVar3 = GetLastError();
          *puVar2 = DVar3;
          FUN_10005cb0(1);
          goto LAB_10009ccb;
        }
        DAT_10016260 = 1;
      }
      switch(param_1) {
      case 2:
        DAT_10016250 = in_stack_00000008;
        break;
      case 0xf:
        DAT_1001625c = in_stack_00000008;
        break;
      case 0x15:
        DAT_10016254 = in_stack_00000008;
        break;
      case 0x16:
        DAT_10016258 = in_stack_00000008;
      }
      FUN_10005cb0(1);
      return;
    }
    if (((param_1 == 8) || (param_1 == 4)) || (param_1 == 0xb)) {
      p_Var4 = __getptd();
      if (*(undefined **)(p_Var4->_con_ch_buf + 4) == &DAT_100162b0) {
        uVar5 = __malloc_dbg(DAT_10016330,2,0x10016264,0x133);
        *(undefined4 *)(p_Var4->_con_ch_buf + 4) = uVar5;
        if (*(int *)(p_Var4->_con_ch_buf + 4) == 0) goto LAB_10009ccb;
        FID_conflict__memcpy(*(void **)(p_Var4->_con_ch_buf + 4),&DAT_100162b0,DAT_10016330);
      }
      local_c = _siglookup(param_1,*(uint *)(p_Var4->_con_ch_buf + 4));
      if (local_c != 0) {
        for (; *(int *)(local_c + 4) == param_1; local_c = local_c + 0xc) {
          *(int *)(local_c + 8) = in_stack_00000008;
        }
        return;
      }
    }
  }
LAB_10009ccb:
  piVar6 = FUN_1000aed0();
  *piVar6 = 0x16;
  return;
}



// Library Function - Single Match
//  _ctrlevent_capture@4
// 
// Library: Visual Studio 1998 Debug
// HandlerRoutine parameter of SetConsoleCtrlHandler
// 

undefined4 _ctrlevent_capture_4(int param_1)

{
  undefined4 uVar1;
  undefined4 local_10;
  code *local_c;
  undefined4 *local_8;
  
  __lock(1);
  if (param_1 == 0) {
    local_8 = &DAT_10016250;
    local_c = DAT_10016250;
    local_10 = 2;
  }
  else {
    local_8 = &DAT_10016254;
    local_c = DAT_10016254;
    local_10 = 0x15;
  }
  if (local_c == (code *)0x0) {
    FUN_10005cb0(1);
    uVar1 = 0;
  }
  else {
    if (local_c == (code *)0x1) {
      FUN_10005cb0(1);
    }
    else {
      *local_8 = 0;
      FUN_10005cb0(1);
      (*local_c)(local_10);
    }
    uVar1 = 1;
  }
  return uVar1;
}



// Library Function - Single Match
//  _raise
// 
// Library: Visual Studio 1998 Debug

int __cdecl _raise(int _SigNum)

{
  bool bVar1;
  uint uVar2;
  int local_20;
  _ptiddata local_1c;
  void *local_18;
  code *local_14;
  code **local_10;
  void *local_c;
  
  bVar1 = false;
  switch(_SigNum) {
  case 2:
    local_10 = &DAT_10016250;
    local_14 = DAT_10016250;
    bVar1 = true;
    break;
  default:
    return -1;
  case 4:
  case 8:
  case 0xb:
    local_1c = __getptd();
    uVar2 = _siglookup(_SigNum,*(uint *)(local_1c->_con_ch_buf + 4));
    local_10 = (code **)(uVar2 + 8);
    local_14 = *local_10;
    break;
  case 0xf:
    local_10 = &DAT_1001625c;
    local_14 = DAT_1001625c;
    bVar1 = true;
    break;
  case 0x15:
    local_10 = &DAT_10016254;
    local_14 = DAT_10016254;
    bVar1 = true;
    break;
  case 0x16:
    local_10 = &DAT_10016258;
    local_14 = DAT_10016258;
    bVar1 = true;
  }
  if (bVar1) {
    __lock(1);
  }
  if (local_14 != (code *)0x1) {
    if (local_14 == (code *)0x0) {
      if (bVar1) {
        FUN_10005cb0(1);
      }
      __exit(3);
    }
    if (((_SigNum == 8) || (_SigNum == 0xb)) || (_SigNum == 4)) {
      local_18 = local_1c->_initaddr;
      local_1c->_initaddr = (void *)0x0;
      if (_SigNum == 8) {
        local_c = local_1c->_initarg;
        local_1c->_initarg = (void *)0x8c;
      }
    }
    if (_SigNum == 8) {
      for (local_20 = DAT_10016328; local_20 < DAT_1001632c + DAT_10016328; local_20 = local_20 + 1)
      {
        *(undefined4 *)(*(int *)(local_1c->_con_ch_buf + 4) + 8 + local_20 * 0xc) = 0;
      }
    }
    else {
      *local_10 = (code *)0x0;
    }
    if (bVar1) {
      FUN_10005cb0(1);
    }
    if (_SigNum == 8) {
      (*local_14)(8,local_1c->_initarg);
    }
    else {
      (*local_14)(_SigNum);
      if ((_SigNum != 0xb) && (_SigNum != 4)) {
        return 0;
      }
    }
    local_1c->_initaddr = local_18;
    if (_SigNum == 8) {
      local_1c->_initarg = local_c;
    }
    return 0;
  }
  if (bVar1) {
    FUN_10005cb0(1);
  }
  return 0;
}



// Library Function - Single Match
//  _siglookup
// 
// Library: Visual Studio 1998 Debug

uint __cdecl _siglookup(int param_1,uint param_2)

{
  uint local_8;
  
  local_8 = param_2;
  do {
    if (*(int *)(local_8 + 4) == param_1) break;
    local_8 = local_8 + 0xc;
  } while (local_8 < DAT_10016334 * 0xc + param_2);
  if (*(int *)(local_8 + 4) != param_1) {
    local_8 = 0;
  }
  return local_8;
}



void ** FUN_1000a0a0(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  return &p_Var1->_initarg;
}



void ** FUN_1000a0c0(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  return &p_Var1->_initaddr;
}



// Library Function - Single Match
//  ___crtMessageBoxA
// 
// Library: Visual Studio 1998 Debug

int __cdecl ___crtMessageBoxA(LPCSTR _LpText,LPCSTR _LpCaption,UINT _UType)

{
  HMODULE hModule;
  int iVar1;
  int local_8;
  
  local_8 = 0;
  if (DAT_10016270 == (FARPROC)0x0) {
    hModule = LoadLibraryA(s_user32_dll_10015624);
    if (hModule != (HMODULE)0x0) {
      DAT_10016270 = GetProcAddress(hModule,s_MessageBoxA_100162a0);
      if (DAT_10016270 != (FARPROC)0x0) {
        DAT_10016274 = GetProcAddress(hModule,s_GetActiveWindow_10016290);
        DAT_10016278 = GetProcAddress(hModule,s_GetLastActivePopup_1001627c);
        goto LAB_1000a165;
      }
    }
    iVar1 = 0;
  }
  else {
LAB_1000a165:
    if (DAT_10016274 != (FARPROC)0x0) {
      local_8 = (*DAT_10016274)();
    }
    if ((local_8 != 0) && (DAT_10016278 != (FARPROC)0x0)) {
      local_8 = (*DAT_10016278)(local_8);
    }
    iVar1 = (*DAT_10016270)(local_8,_LpText,_LpCaption,_UType);
  }
  return iVar1;
}



char * __cdecl FUN_1000a1c0(char *param_1,char *param_2,int param_3)

{
  char *pcVar1;
  char *pcVar2;
  
  pcVar1 = param_1;
  if (param_3 != 0) {
    do {
      pcVar2 = pcVar1;
      if (*param_2 == '\0') break;
      pcVar2 = pcVar1 + 1;
      *pcVar1 = *param_2;
      param_3 = param_3 + -1;
      param_2 = param_2 + 1;
      pcVar1 = pcVar2;
    } while (param_3 != 0);
    for (; param_3 != 0; param_3 = param_3 + -1) {
      *pcVar2 = '\0';
      pcVar2 = pcVar2 + 1;
    }
  }
  return param_1;
}



void FUN_1000a290(void)

{
  _ptiddata p_Var1;
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  uStack_14 = *unaff_FS_OFFSET;
  puStack_c = &DAT_10013108;
  puStack_10 = &LAB_1000a414;
  *unaff_FS_OFFSET = &uStack_14;
  local_8 = 0;
  p_Var1 = __getptd();
  if (p_Var1->_tpxcptinfoptrs != (void *)0x0) {
    local_8 = 1;
    p_Var1 = __getptd();
    (*(code *)p_Var1->_tpxcptinfoptrs)();
  }
  local_8 = 0xffffffff;
                    // WARNING: Subroutine does not return
  _abort();
}



void FUN_1000a330(void)

{
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  uStack_14 = *unaff_FS_OFFSET;
  puStack_c = &DAT_10013120;
  puStack_10 = &LAB_1000a414;
  *unaff_FS_OFFSET = &uStack_14;
  if (PTR_FUN_100162ac != (undefined *)0x0) {
    local_8 = 1;
    (*(code *)PTR_FUN_100162ac)();
  }
  local_8 = 0xffffffff;
  FUN_1000a290();
  return;
}



// Library Function - Single Match
//  int __cdecl _ValidateRead(void const *,unsigned int)
// 
// Library: Visual Studio 1998 Release

int __cdecl _ValidateRead(void *param_1,uint param_2)

{
  BOOL BVar1;
  
  BVar1 = IsBadReadPtr(param_1,param_2);
  return (uint)(BVar1 == 0);
}



// Library Function - Multiple Matches With Different Base Names
//  int __cdecl _ValidateRead(void const *,unsigned int)
//  int __cdecl _ValidateWrite(void *,unsigned int)
// 
// Library: Visual Studio 1998 Release

int __cdecl _ValidateWrite(void *param_1,uint param_2)

{
  BOOL BVar1;
  
  BVar1 = IsBadWritePtr(param_1,param_2);
  return (uint)(BVar1 == 0);
}



// Library Function - Single Match
//  int __cdecl _ValidateExecute(int (__stdcall*)(void))
// 
// Library: Visual Studio 1998 Release

int __cdecl _ValidateExecute(_func_int *param_1)

{
  BOOL BVar1;
  
  BVar1 = IsBadCodePtr((FARPROC)param_1);
  return (uint)(BVar1 == 0);
}



void FUN_1000a4d1(int param_1)

{
  __local_unwind2(*(int *)(param_1 + 0x18),*(int *)(param_1 + 0x1c));
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  _memcpy
//  _memmove
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

void * __cdecl FID_conflict__memcpy(void *_Dst,void *_Src,size_t _Size)

{
  uint uVar1;
  int in_EDX;
  uint uVar2;
  undefined4 *puVar3;
  undefined *puVar4;
  undefined4 *puVar5;
  undefined *puVar6;
  
  if ((_Src < _Dst) && (_Dst < (void *)((int)_Src + _Size))) {
    puVar3 = (undefined4 *)((int)_Src + _Size);
    puVar5 = (undefined4 *)((int)_Dst + _Size);
    if (((uint)puVar5 & 3) == 0) {
      uVar1 = _Size >> 2;
      while( true ) {
        puVar5 = puVar5 + -1;
        puVar3 = puVar3 + -1;
        if (uVar1 == 0) break;
        uVar1 = uVar1 - 1;
        *puVar5 = *puVar3;
      }
      switch(_Size & 3) {
      case 1:
switchD_1000a5b9_caseD_1:
        *(undefined *)((int)puVar5 + 3) = *(undefined *)((int)puVar3 + 3);
        return _Dst;
      case 2:
switchD_1000a5b9_caseD_2:
        *(undefined2 *)((int)puVar5 + 2) = *(undefined2 *)((int)puVar3 + 2);
        return _Dst;
      case 3:
switchD_1000a5b9_caseD_3:
        *(undefined2 *)((int)puVar5 + 2) = *(undefined2 *)((int)puVar3 + 2);
        *(undefined *)((int)puVar5 + 1) = *(undefined *)((int)puVar3 + 1);
        return _Dst;
      }
    }
    else {
      puVar4 = (undefined *)((int)puVar3 + -1);
      puVar6 = (undefined *)((int)puVar5 + -1);
      if (_Size < 0xd) {
        for (; _Size != 0; _Size = _Size - 1) {
          *puVar6 = *puVar4;
          puVar4 = puVar4 + -1;
          puVar6 = puVar6 + -1;
        }
        return _Dst;
      }
      uVar2 = -in_EDX & 3;
      uVar1 = _Size - uVar2;
      for (; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar6 = *puVar4;
        puVar4 = puVar4 + -1;
        puVar6 = puVar6 + -1;
      }
      puVar3 = (undefined4 *)(puVar4 + -3);
      puVar5 = (undefined4 *)(puVar6 + -3);
      for (uVar2 = uVar1 >> 2; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar5 = *puVar3;
        puVar3 = puVar3 + -1;
        puVar5 = puVar5 + -1;
      }
      switch(uVar1 & 3) {
      case 1:
        goto switchD_1000a5b9_caseD_1;
      case 2:
        goto switchD_1000a5b9_caseD_2;
      case 3:
        goto switchD_1000a5b9_caseD_3;
      }
    }
    return _Dst;
  }
  puVar3 = (undefined4 *)_Dst;
  if (((uint)_Dst & 3) == 0) {
                    // WARNING: Load size is inaccurate
    for (uVar1 = _Size >> 2; uVar1 != 0; uVar1 = uVar1 - 1) {
      *puVar3 = *_Src;
      _Src = (undefined4 *)((int)_Src + 4);
      puVar3 = puVar3 + 1;
    }
    switch(_Size & 3) {
    case 1:
switchD_1000a520_caseD_1:
                    // WARNING: Load size is inaccurate
      *(undefined *)puVar3 = *_Src;
      return _Dst;
    case 2:
switchD_1000a520_caseD_2:
                    // WARNING: Load size is inaccurate
      *(undefined2 *)puVar3 = *_Src;
      return _Dst;
    case 3:
switchD_1000a520_caseD_3:
                    // WARNING: Load size is inaccurate
      *(undefined2 *)puVar3 = *_Src;
      *(undefined *)((int)puVar3 + 2) = *(undefined *)((int)_Src + 2);
      return _Dst;
    }
  }
  else {
    puVar4 = (undefined *)_Dst;
    if (_Size < 0xd) {
                    // WARNING: Load size is inaccurate
      for (; _Size != 0; _Size = _Size - 1) {
        *puVar4 = *_Src;
        _Src = (undefined *)((int)_Src + 1);
        puVar4 = puVar4 + 1;
      }
      return _Dst;
    }
    uVar2 = -(int)_Dst & 3;
    uVar1 = _Size - uVar2;
                    // WARNING: Load size is inaccurate
    for (; uVar2 != 0; uVar2 = uVar2 - 1) {
      *(undefined *)puVar3 = *_Src;
      _Src = (undefined4 *)((int)_Src + 1);
      puVar3 = (undefined4 *)((int)puVar3 + 1);
    }
                    // WARNING: Load size is inaccurate
    for (uVar2 = uVar1 >> 2; uVar2 != 0; uVar2 = uVar2 - 1) {
      *puVar3 = *_Src;
      _Src = (undefined4 *)((int)_Src + 4);
      puVar3 = puVar3 + 1;
    }
    switch(uVar1 & 3) {
    case 1:
      goto switchD_1000a520_caseD_1;
    case 2:
      goto switchD_1000a520_caseD_2;
    case 3:
      goto switchD_1000a520_caseD_3;
    }
  }
  return _Dst;
}



// Library Function - Single Match
//  __XcptFilter
// 
// Library: Visual Studio 1998 Debug

int __cdecl __XcptFilter(ulong _ExceptionNum,_EXCEPTION_POINTERS *_ExceptionPtr)

{
  code *pcVar1;
  void *pvVar2;
  void *pvVar3;
  _ptiddata p_Var4;
  int *piVar5;
  int iVar6;
  int local_18;
  
  p_Var4 = __getptd();
  piVar5 = _xcptlookup(_ExceptionNum,*(int **)(p_Var4->_con_ch_buf + 4));
  if ((piVar5 == (int *)0x0) || (piVar5[2] == 0)) {
    iVar6 = UnhandledExceptionFilter(_ExceptionPtr);
  }
  else if (piVar5[2] == 5) {
    piVar5[2] = 0;
    iVar6 = 1;
  }
  else if (piVar5[2] == 1) {
    iVar6 = -1;
  }
  else {
    pcVar1 = (code *)piVar5[2];
    pvVar2 = p_Var4->_initaddr;
    p_Var4->_initaddr = _ExceptionPtr;
    if (piVar5[1] == 8) {
      for (local_18 = DAT_10016328; local_18 < DAT_1001632c + DAT_10016328; local_18 = local_18 + 1)
      {
        *(undefined4 *)(*(int *)(p_Var4->_con_ch_buf + 4) + 8 + local_18 * 0xc) = 0;
      }
      pvVar3 = p_Var4->_initarg;
      if (*piVar5 == -0x3fffff72) {
        p_Var4->_initarg = (void *)0x83;
      }
      else if (*piVar5 == -0x3fffff70) {
        p_Var4->_initarg = (void *)0x81;
      }
      else if (*piVar5 == -0x3fffff6f) {
        p_Var4->_initarg = (void *)0x84;
      }
      else if (*piVar5 == -0x3fffff6d) {
        p_Var4->_initarg = (void *)0x85;
      }
      else if (*piVar5 == -0x3fffff73) {
        p_Var4->_initarg = (void *)0x82;
      }
      else if (*piVar5 == -0x3fffff71) {
        p_Var4->_initarg = (void *)0x86;
      }
      else if (*piVar5 == -0x3fffff6e) {
        p_Var4->_initarg = (void *)0x8a;
      }
      (*pcVar1)(8,p_Var4->_initarg);
      p_Var4->_initarg = pvVar3;
    }
    else {
      piVar5[2] = 0;
      (*pcVar1)(piVar5[1]);
    }
    p_Var4->_initaddr = pvVar2;
    iVar6 = -1;
  }
  return iVar6;
}



// Library Function - Single Match
//  _xcptlookup
// 
// Library: Visual Studio 1998 Debug

int * __cdecl _xcptlookup(int param_1,int *param_2)

{
  int *local_8;
  
  local_8 = param_2;
  do {
    if (*local_8 == param_1) break;
    local_8 = local_8 + 3;
  } while (local_8 < param_2 + DAT_10016334 * 3);
  if (*local_8 != param_1) {
    local_8 = (int *)0x0;
  }
  return local_8;
}



// Library Function - Single Match
//  _wcslen
// 
// Library: Visual Studio 1998 Debug

size_t __cdecl _wcslen(wchar_t *_Str)

{
  wchar_t *pwVar1;
  wchar_t wVar2;
  wchar_t *local_8;
  
  local_8 = _Str;
  do {
    pwVar1 = local_8 + 1;
    wVar2 = *local_8;
    local_8 = pwVar1;
  } while (wVar2 != L'\0');
  return ((int)pwVar1 - (int)_Str >> 1) - 1;
}



// Library Function - Multiple Matches With Different Base Names
//  _memcpy
//  _memmove
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

void * __cdecl FID_conflict__memcpy(void *_Dst,void *_Src,size_t _Size)

{
  uint uVar1;
  int in_EDX;
  uint uVar2;
  undefined4 *puVar3;
  undefined *puVar4;
  undefined4 *puVar5;
  undefined *puVar6;
  
  if ((_Src < _Dst) && (_Dst < (void *)((int)_Src + _Size))) {
    puVar3 = (undefined4 *)((int)_Src + _Size);
    puVar5 = (undefined4 *)((int)_Dst + _Size);
    if (((uint)puVar5 & 3) == 0) {
      uVar1 = _Size >> 2;
      while( true ) {
        puVar5 = puVar5 + -1;
        puVar3 = puVar3 + -1;
        if (uVar1 == 0) break;
        uVar1 = uVar1 - 1;
        *puVar5 = *puVar3;
      }
      switch(_Size & 3) {
      case 1:
switchD_1000a9c9_caseD_1:
        *(undefined *)((int)puVar5 + 3) = *(undefined *)((int)puVar3 + 3);
        return _Dst;
      case 2:
switchD_1000a9c9_caseD_2:
        *(undefined2 *)((int)puVar5 + 2) = *(undefined2 *)((int)puVar3 + 2);
        return _Dst;
      case 3:
switchD_1000a9c9_caseD_3:
        *(undefined2 *)((int)puVar5 + 2) = *(undefined2 *)((int)puVar3 + 2);
        *(undefined *)((int)puVar5 + 1) = *(undefined *)((int)puVar3 + 1);
        return _Dst;
      }
    }
    else {
      puVar4 = (undefined *)((int)puVar3 + -1);
      puVar6 = (undefined *)((int)puVar5 + -1);
      if (_Size < 0xd) {
        for (; _Size != 0; _Size = _Size - 1) {
          *puVar6 = *puVar4;
          puVar4 = puVar4 + -1;
          puVar6 = puVar6 + -1;
        }
        return _Dst;
      }
      uVar2 = -in_EDX & 3;
      uVar1 = _Size - uVar2;
      for (; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar6 = *puVar4;
        puVar4 = puVar4 + -1;
        puVar6 = puVar6 + -1;
      }
      puVar3 = (undefined4 *)(puVar4 + -3);
      puVar5 = (undefined4 *)(puVar6 + -3);
      for (uVar2 = uVar1 >> 2; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar5 = *puVar3;
        puVar3 = puVar3 + -1;
        puVar5 = puVar5 + -1;
      }
      switch(uVar1 & 3) {
      case 1:
        goto switchD_1000a9c9_caseD_1;
      case 2:
        goto switchD_1000a9c9_caseD_2;
      case 3:
        goto switchD_1000a9c9_caseD_3;
      }
    }
    return _Dst;
  }
  puVar3 = (undefined4 *)_Dst;
  if (((uint)_Dst & 3) == 0) {
                    // WARNING: Load size is inaccurate
    for (uVar1 = _Size >> 2; uVar1 != 0; uVar1 = uVar1 - 1) {
      *puVar3 = *_Src;
      _Src = (undefined4 *)((int)_Src + 4);
      puVar3 = puVar3 + 1;
    }
    switch(_Size & 3) {
    case 1:
switchD_1000a930_caseD_1:
                    // WARNING: Load size is inaccurate
      *(undefined *)puVar3 = *_Src;
      return _Dst;
    case 2:
switchD_1000a930_caseD_2:
                    // WARNING: Load size is inaccurate
      *(undefined2 *)puVar3 = *_Src;
      return _Dst;
    case 3:
switchD_1000a930_caseD_3:
                    // WARNING: Load size is inaccurate
      *(undefined2 *)puVar3 = *_Src;
      *(undefined *)((int)puVar3 + 2) = *(undefined *)((int)_Src + 2);
      return _Dst;
    }
  }
  else {
    puVar4 = (undefined *)_Dst;
    if (_Size < 0xd) {
                    // WARNING: Load size is inaccurate
      for (; _Size != 0; _Size = _Size - 1) {
        *puVar4 = *_Src;
        _Src = (undefined *)((int)_Src + 1);
        puVar4 = puVar4 + 1;
      }
      return _Dst;
    }
    uVar2 = -(int)_Dst & 3;
    uVar1 = _Size - uVar2;
                    // WARNING: Load size is inaccurate
    for (; uVar2 != 0; uVar2 = uVar2 - 1) {
      *(undefined *)puVar3 = *_Src;
      _Src = (undefined4 *)((int)_Src + 1);
      puVar3 = (undefined4 *)((int)puVar3 + 1);
    }
                    // WARNING: Load size is inaccurate
    for (uVar2 = uVar1 >> 2; uVar2 != 0; uVar2 = uVar2 - 1) {
      *puVar3 = *_Src;
      _Src = (undefined4 *)((int)_Src + 4);
      puVar3 = puVar3 + 1;
    }
    switch(uVar1 & 3) {
    case 1:
      goto switchD_1000a930_caseD_1;
    case 2:
      goto switchD_1000a930_caseD_2;
    case 3:
      goto switchD_1000a930_caseD_3;
    }
  }
  return _Dst;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_1000aa50(uint *param_1,uint *param_2,int param_3)

{
  code *pcVar1;
  DWORD DVar2;
  char *pcVar3;
  char *pcVar4;
  int _Radix;
  uint local_32c;
  uint local_110 [65];
  int local_c;
  uint *local_8;
  
  if ((DAT_10014cc0 == 1) || ((DAT_10014cc0 == 0 && (DAT_10014cc4 == 1)))) {
    if ((_DAT_10016004 & 0x10c) == 0) {
      _setvbuf((FILE *)&DAT_10015ff8,(char *)0x0,4,0);
    }
    FID_conflict__fwprintf
              ((FILE *)&DAT_10015ff8,(wchar_t *)s_Assertion_failed___s__file__s__l_10016358,
               (char *)param_1,(char *)param_2,param_3);
    local_32c = 0x1000aada;
    _fflush((FILE *)&DAT_10015ff8);
  }
  else {
    FUN_100097a0(&local_32c,(uint *)s_Assertion_failed__10015590);
    FUN_100097a8(&local_32c,(uint *)PTR_DAT_10016388);
    FUN_100097a8(&local_32c,(uint *)s_Program__1001644c);
    DVar2 = GetModuleFileNameA((HMODULE)0x0,(LPSTR)local_110,0x104);
    if (DVar2 == 0) {
      FUN_100097a0(local_110,(uint *)s_<program_name_unknown>_10015754);
    }
    local_8 = local_110;
    pcVar3 = FUN_10009720(local_110);
    if ((char *)0x3c < pcVar3 + 0xb) {
      pcVar3 = FUN_10009720(local_110);
      local_8 = (uint *)((int)local_8 + (int)(pcVar3 + -0x31));
      FUN_1000a1c0((char *)local_8,PTR_DAT_10016380,3);
    }
    FUN_100097a8(&local_32c,local_8);
    FUN_100097a8(&local_32c,(uint *)PTR_DAT_10016384);
    FUN_100097a8(&local_32c,(uint *)s_File__10016444);
    local_8 = param_2;
    pcVar3 = FUN_10009720(param_2);
    if ((char *)0x3c < pcVar3 + 8) {
      pcVar3 = FUN_10009720(param_2);
      local_8 = (uint *)((int)local_8 + (int)(pcVar3 + -0x34));
      FUN_1000a1c0((char *)local_8,PTR_DAT_10016380,3);
    }
    FUN_100097a8(&local_32c,local_8);
    FUN_100097a8(&local_32c,(uint *)PTR_DAT_10016384);
    FUN_100097a8(&local_32c,(uint *)s_Line__1001643c);
    _Radix = 10;
    pcVar3 = FUN_10009720(&local_32c);
    __itoa(param_3,(char *)((int)&local_32c + (int)pcVar3),_Radix);
    FUN_100097a8(&local_32c,(uint *)PTR_DAT_10016388);
    FUN_100097a8(&local_32c,(uint *)s_Expression__100156c8);
    pcVar3 = FUN_10009720(param_1);
    pcVar4 = FUN_10009720(&local_32c);
    if (pcVar3 + (int)pcVar4 + 0xb0 < (char *)0x21d) {
      FUN_100097a8(&local_32c,param_1);
    }
    else {
      pcVar3 = FUN_10009720(&local_32c);
      FUN_1000caa0((char *)&local_32c,(char *)param_1,0x21c - (int)(pcVar3 + 0xb1));
      FUN_100097a8(&local_32c,(uint *)PTR_DAT_10016380);
    }
    FUN_100097a8(&local_32c,(uint *)PTR_DAT_10016388);
    FUN_100097a8(&local_32c,(uint *)s_For_information_on_how_your_prog_100163cc);
    FUN_100097a8(&local_32c,(uint *)PTR_DAT_10016388);
    FUN_100097a8(&local_32c,(uint *)s__Press_Retry_to_debug_the_applic_1001638c);
    local_c = ___crtMessageBoxA((LPCSTR)&local_32c,s_Microsoft_Visual_C___Runtime_Lib_10015d0c,
                                0x12012);
    if (local_c == 3) {
      _raise(0x16);
      __exit(3);
    }
    if (local_c == 4) {
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    if (local_c == 5) {
      return;
    }
  }
                    // WARNING: Subroutine does not return
  _abort();
}



// Library Function - Single Match
//  __dosmaperr
// 
// Library: Visual Studio 1998 Debug

void __cdecl __dosmaperr(ulong param_1)

{
  ulong *puVar1;
  int *piVar2;
  uint local_8;
  
  puVar1 = FUN_1000aef0();
  *puVar1 = param_1;
  local_8 = 0;
  while( true ) {
    if (0x2c < local_8) {
      if ((param_1 < 0x13) || (0x24 < param_1)) {
        if ((param_1 < 0xbc) || (0xca < param_1)) {
          piVar2 = FUN_1000aed0();
          *piVar2 = 0x16;
        }
        else {
          piVar2 = FUN_1000aed0();
          *piVar2 = 8;
        }
      }
      else {
        piVar2 = FUN_1000aed0();
        *piVar2 = 0xd;
      }
      return;
    }
    if (*(ulong *)(&DAT_10016458 + local_8 * 8) == param_1) break;
    local_8 = local_8 + 1;
  }
  piVar2 = FUN_1000aed0();
  *piVar2 = *(int *)(&DAT_1001645c + local_8 * 8);
  return;
}



int * FUN_1000aed0(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  return &p_Var1->_terrno;
}



ulong * FUN_1000aef0(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  return &p_Var1->_tdoserrno;
}



// Library Function - Single Match
//  __flsbuf
// 
// Library: Visual Studio 1998 Debug

int __cdecl __flsbuf(int _Ch,FILE *_File)

{
  code *pcVar1;
  FILE *_File_00;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined *local_1c;
  uint local_14;
  uint local_c;
  
  if ((_File == (FILE *)0x0) &&
     (uVar2 = FUN_10005fc0(2,s__flsbuf_c_10016600,0x69,(uint *)0x0,s_str____NULL_1001660c),
     uVar2 == 1)) {
    pcVar1 = (code *)swi(3);
    iVar3 = (*pcVar1)();
    return iVar3;
  }
  _File_00 = _File;
  uVar2 = _File->_file;
  if (((*(byte *)&_File->_flag & 0x82) == 0) || ((*(byte *)&_File->_flag & 0x40) != 0)) {
    _File->_flag = _File->_flag | 0x20;
    uVar2 = 0xffffffff;
  }
  else {
    if ((*(byte *)&_File->_flag & 1) != 0) {
      _File->_cnt = 0;
      if ((*(byte *)&_File->_flag & 0x10) == 0) {
        _File->_flag = _File->_flag | 0x20;
        return -1;
      }
      _File->_ptr = _File->_base;
      _File->_flag = _File->_flag & 0xfffffffe;
    }
    _File->_flag = _File->_flag | 2;
    _File->_flag = _File->_flag & 0xffffffef;
    _File->_cnt = 0;
    local_14 = _File->_cnt;
    if (((_File->_flag & 0x10cU) == 0) &&
       (((_File != (FILE *)0x10015fd8 && (_File != (FILE *)&DAT_10015ff8)) ||
        (iVar3 = __isatty(uVar2), iVar3 == 0)))) {
      __getbuf(_File_00);
    }
    if ((_File_00->_flag & 0x108U) == 0) {
      local_c = 1;
      local_14 = FUN_1000cd30(uVar2,(char *)&_Ch,1);
    }
    else {
      if (((int)_File_00->_ptr - (int)_File_00->_base < 0) &&
         (uVar4 = FUN_10005fc0(2,s__flsbuf_c_10016600,0xa0,(uint *)0x0,
                               s___inconsistent_IOB_fields___stre_100165c0), uVar4 == 1)) {
        pcVar1 = (code *)swi(3);
        iVar3 = (*pcVar1)();
        return iVar3;
      }
      local_c = (int)_File_00->_ptr - (int)_File_00->_base;
      _File_00->_ptr = _File_00->_base + 1;
      _File_00->_cnt = _File_00->_bufsiz + -1;
      if ((int)local_c < 1) {
        if (uVar2 == 0xffffffff) {
          local_1c = &DAT_100157a8;
        }
        else {
          local_1c = (undefined *)
                     (*(int *)((int)&DAT_10019610 + ((int)(uVar2 & 0xffffffe0) >> 3)) +
                     (uVar2 & 0x1f) * 0x24);
        }
        if ((local_1c[4] & 0x20) != 0) {
          __lseek(uVar2,0,2);
        }
      }
      else {
        local_14 = FUN_1000cd30(uVar2,_File_00->_base,local_c);
      }
      *_File_00->_base = (char)_Ch;
    }
    if (local_14 == local_c) {
      uVar2 = _Ch & 0xff;
    }
    else {
      _File_00->_flag = _File_00->_flag | 0x20;
      uVar2 = 0xffffffff;
    }
  }
  return uVar2;
}



int __cdecl FUN_1000b1b0(FILE *param_1,byte *param_2,undefined4 *param_3)

{
  byte *pbVar1;
  uint *puVar2;
  char *pcVar3;
  short sVar4;
  code *pcVar5;
  uint uVar6;
  undefined4 uVar7;
  int iVar8;
  bool bVar9;
  undefined8 uVar10;
  CHAR local_294 [4];
  uint *local_290;
  char *local_28c;
  int local_288;
  undefined8 local_284;
  int local_27c;
  undefined8 local_278;
  undefined4 local_270;
  undefined4 local_26c;
  int *local_268;
  int local_264;
  CHAR local_260 [4];
  int local_25c;
  uint *local_258;
  uint *local_254;
  short *local_250;
  undefined2 local_24c;
  char local_248;
  char local_247;
  int local_244;
  char *local_240;
  int local_23c;
  uint local_238;
  uint local_234;
  int local_230;
  undefined4 local_22c;
  int local_228;
  uint *local_224;
  int local_220;
  byte local_21c;
  int local_218;
  uint local_214;
  int local_210;
  uint local_20c [127];
  undefined local_d [5];
  int local_8;
  
  local_218 = 0;
  local_228 = 0;
  pbVar1 = param_2;
  do {
    param_2 = pbVar1;
    local_21c = *param_2;
    pbVar1 = param_2 + 1;
    if ((local_21c == 0) || (local_218 < 0)) {
      return local_218;
    }
    if (((char)local_21c < ' ') || ('x' < (char)local_21c)) {
      local_238 = 0;
    }
    else {
      local_238 = (int)*(char *)((int)&PTR_LAB_10013118 + (int)(char)local_21c) & 0xf;
    }
    local_228 = (int)(char)(&DAT_10013138)[local_238 * 8 + local_228] >> 4;
    switch(local_228) {
    case 0:
      goto switchD_1000c086_caseD_0;
    case 1:
      local_d._1_4_ = 0;
      local_244 = 0;
      local_230 = 0;
      local_210 = 0;
      local_214 = 0;
      local_8 = -1;
      local_220 = 0;
      break;
    case 2:
      switch(local_21c) {
      case 0x20:
        local_214 = local_214 | 2;
        break;
      case 0x23:
        local_214 = local_214 | 0x80;
        break;
      case 0x2b:
        local_214 = local_214 | 1;
        break;
      case 0x2d:
        local_214 = local_214 | 4;
        break;
      case 0x30:
        local_214 = local_214 | 8;
      }
      break;
    case 3:
      if (local_21c == 0x2a) {
        local_230 = _get_int_arg((int *)&param_3);
        if (local_230 < 0) {
          local_214 = local_214 | 4;
          local_230 = -local_230;
        }
      }
      else {
        local_230 = (char)local_21c + -0x30 + local_230 * 10;
      }
      break;
    case 4:
      local_8 = 0;
      break;
    case 5:
      if (local_21c == 0x2a) {
        local_8 = _get_int_arg((int *)&param_3);
        if (local_8 < 0) {
          local_8 = -1;
        }
      }
      else {
        local_8 = (char)local_21c + -0x30 + local_8 * 10;
      }
      break;
    case 6:
      switch(local_21c) {
      case 0x49:
        if ((*pbVar1 == 0x36) && (param_2[2] == 0x34)) {
          local_214 = local_214 | 0x8000;
          pbVar1 = param_2 + 3;
        }
        else {
          local_228 = 0;
switchD_1000c086_caseD_0:
          local_220 = 0;
          if ((*(ushort *)(PTR_DAT_10015da0 + (uint)local_21c * 2) & 0x8000) != 0) {
            _write_char((int)(char)local_21c,param_1,&local_218);
            local_21c = *pbVar1;
            pbVar1 = param_2 + 2;
            if ((local_21c == 0) &&
               (uVar6 = FUN_10005fc0(2,s_output_c_10016638,0x185,(uint *)0x0,
                                     s_ch_____T___0___10016644), uVar6 == 1)) {
              pcVar5 = (code *)swi(3);
              iVar8 = (*pcVar5)();
              return iVar8;
            }
          }
          param_2 = pbVar1;
          _write_char((int)(char)local_21c,param_1,&local_218);
          pbVar1 = param_2;
        }
        break;
      case 0x68:
        local_214 = local_214 | 0x20;
        break;
      case 0x6c:
        local_214 = local_214 | 0x10;
        break;
      case 0x77:
        local_214 = local_214 | 0x800;
      }
      break;
    case 7:
      puVar2 = local_224;
      switch(local_21c) {
      case 0x43:
        if ((local_214 & 0x830) == 0) {
          local_214 = local_214 | 0x800;
        }
      case 99:
        if ((local_214 & 0x810) == 0) {
          uVar7 = _get_int_arg((int *)&param_3);
          local_24c._0_1_ = (CHAR)uVar7;
          local_20c[0]._0_1_ = (CHAR)local_24c;
          local_240 = (char *)0x1;
          local_24c = (short)uVar7;
        }
        else {
          uVar7 = _get_short_arg((int *)&param_3);
          local_22c = CONCAT22(local_22c._2_2_,(short)uVar7);
          local_240 = (char *)FUN_1000d3b0((LPSTR)local_20c,local_22c);
          if ((int)local_240 < 0) {
            local_244 = 1;
          }
        }
        puVar2 = local_20c;
        break;
      case 0x45:
      case 0x47:
        local_d._1_4_ = 1;
        local_21c = local_21c + 0x20;
      case 0x65:
      case 0x66:
      case 0x67:
        local_214 = local_214 | 0x40;
        local_224 = local_20c;
        if (local_8 < 0) {
          local_8 = 6;
        }
        else if ((local_8 == 0) && (local_21c == 0x67)) {
          local_8 = 1;
        }
        local_270 = *param_3;
        local_26c = param_3[1];
        param_3 = param_3 + 2;
        (*(code *)PTR___fptrap_10016698)
                  (&local_270,local_224,(int)(char)local_21c,local_8,local_d._1_4_);
        if (((local_214 & 0x80) != 0) && (local_8 == 0)) {
          (*(code *)PTR___fptrap_100166a4)(local_224);
        }
        if ((local_21c == 0x67) && ((local_214 & 0x80) == 0)) {
          (*(code *)PTR___fptrap_1001669c)(local_224);
        }
        if (*(char *)local_224 == '-') {
          local_214 = local_214 | 0x100;
          local_224 = (uint *)((int)local_224 + 1);
        }
        local_240 = FUN_10009720(local_224);
        puVar2 = local_224;
        break;
      case 0x53:
        if ((local_214 & 0x830) == 0) {
          local_214 = local_214 | 0x800;
        }
      case 0x73:
        if (local_8 == -1) {
          local_25c = 0x7fffffff;
        }
        else {
          local_25c = local_8;
        }
        local_224 = (uint *)_get_int_arg((int *)&param_3);
        if ((local_214 & 0x810) == 0) {
          if (local_224 == (uint *)0x0) {
            local_224 = (uint *)PTR_DAT_10016630;
          }
          for (local_254 = local_224; (local_25c != 0 && (*(char *)local_254 != '\0'));
              local_254 = (uint *)((int)local_254 + 1)) {
            local_25c = local_25c + -1;
          }
          local_240 = (char *)((int)local_254 - (int)local_224);
          local_25c = local_25c + -1;
          puVar2 = local_224;
        }
        else {
          if (local_224 == (uint *)0x0) {
            local_224 = (uint *)PTR_DAT_10016634;
          }
          local_220 = 1;
          local_258 = local_224;
          local_240 = (char *)0x0;
          while (((puVar2 = local_224, (int)local_240 < local_25c && (*(short *)local_258 != 0)) &&
                 (local_264 = FUN_1000d3b0(local_260,
                                           CONCAT22((short)((uint)local_258 >> 0x10),
                                                    *(short *)local_258)), puVar2 = local_224,
                 local_264 != 0))) {
            local_240 = local_240 + local_264;
            local_258 = (uint *)((int)local_258 + 2);
          }
        }
        break;
      case 0x5a:
        local_250 = (short *)_get_int_arg((int *)&param_3);
        if ((local_250 == (short *)0x0) || (*(int *)(local_250 + 2) == 0)) {
          local_224 = (uint *)PTR_DAT_10016630;
          local_240 = FUN_10009720((uint *)PTR_DAT_10016630);
          puVar2 = local_224;
        }
        else if ((local_214 & 0x800) == 0) {
          local_220 = 0;
          local_240 = (char *)(int)*local_250;
          puVar2 = *(uint **)(local_250 + 2);
        }
        else {
          local_240 = (char *)((uint)(int)*local_250 >> 1);
          local_220 = 1;
          puVar2 = *(uint **)(local_250 + 2);
        }
        break;
      case 100:
      case 0x69:
        local_214 = local_214 | 0x40;
        local_234 = 10;
        goto LAB_1000baec;
      case 0x6e:
        local_268 = (int *)_get_int_arg((int *)&param_3);
        if ((local_214 & 0x20) == 0) {
          *local_268 = local_218;
        }
        else {
          *(short *)local_268 = (short)local_218;
        }
        local_244 = 1;
        puVar2 = local_224;
        break;
      case 0x6f:
        local_234 = 8;
        if ((local_214 & 0x80) != 0) {
          local_214 = local_214 | 0x200;
        }
        goto LAB_1000baec;
      case 0x70:
        local_8 = 8;
      case 0x58:
        local_23c = 7;
        goto LAB_1000ba8f;
      case 0x75:
        local_234 = 10;
        goto LAB_1000baec;
      case 0x78:
        local_23c = 0x27;
LAB_1000ba8f:
        local_234 = 0x10;
        if ((local_214 & 0x80) != 0) {
          local_248 = '0';
          local_247 = (char)local_23c + 'Q';
          local_210 = 2;
        }
LAB_1000baec:
        if ((local_214 & 0x8000) == 0) {
          if ((local_214 & 0x20) == 0) {
            if ((local_214 & 0x40) == 0) {
              uVar6 = _get_int_arg((int *)&param_3);
              local_284 = (ulonglong)uVar6;
            }
            else {
              iVar8 = _get_int_arg((int *)&param_3);
              local_284 = (ulonglong)iVar8;
            }
          }
          else if ((local_214 & 0x40) == 0) {
            uVar6 = _get_int_arg((int *)&param_3);
            local_284 = (ulonglong)(uVar6 & 0xffff);
          }
          else {
            uVar7 = _get_int_arg((int *)&param_3);
            local_284 = (ulonglong)(int)(short)uVar7;
          }
        }
        else {
          local_284 = _get_int64_arg((int *)&param_3);
        }
        if ((((local_214 & 0x40) == 0) || (0 < local_284._4_4_)) || (-1 < (longlong)local_284)) {
          local_278 = local_284;
        }
        else {
          local_278 = CONCAT44(-(local_284._4_4_ + (uint)((int)local_284 != 0)),-(int)local_284);
          local_214 = local_214 | 0x100;
        }
        if ((local_214 & 0x8000) == 0) {
          local_278 = local_278 & 0xffffffff;
        }
        if (local_8 < 0) {
          local_8 = 1;
        }
        else {
          local_214 = local_214 & 0xfffffff7;
        }
        if ((local_278._4_4_ == 0) && ((uint)local_278 == 0)) {
          local_210 = 0;
        }
        local_224 = (uint *)local_d;
        while( true ) {
          iVar8 = local_8 + -1;
          if (((local_8 < 1) && (local_278._4_4_ == 0)) && ((uint)local_278 == 0)) break;
          local_8 = iVar8;
          uVar10 = __aullrem((uint)local_278,local_278._4_4_,local_234,(int)local_234 >> 0x1f);
          local_27c = (int)uVar10 + 0x30;
          local_278 = __aulldiv((uint)local_278,local_278._4_4_,local_234,(int)local_234 >> 0x1f);
          if (0x39 < local_27c) {
            local_27c = local_27c + local_23c;
          }
          *(char *)local_224 = (char)local_27c;
          local_224 = (uint *)((int)local_224 + -1);
        }
        local_240 = local_d + -(int)local_224;
        puVar2 = (uint *)((int)local_224 + 1);
        local_8 = iVar8;
        if (((local_214 & 0x200) != 0) && ((*(char *)puVar2 != '0' || (local_240 == (char *)0x0))))
        {
          *(char *)local_224 = '0';
          local_240 = local_d + -(int)local_224 + 1;
          puVar2 = local_224;
        }
      }
      local_224 = puVar2;
      if (local_244 == 0) {
        if ((local_214 & 0x40) != 0) {
          if ((local_214 & 0x100) == 0) {
            if ((local_214 & 1) == 0) {
              if ((local_214 & 2) != 0) {
                local_248 = ' ';
                local_210 = 1;
              }
            }
            else {
              local_248 = '+';
              local_210 = 1;
            }
          }
          else {
            local_248 = '-';
            local_210 = 1;
          }
        }
        local_288 = (local_230 - (int)local_240) - local_210;
        if ((local_214 & 0xc) == 0) {
          _write_multi_char(0x20,local_288,param_1,&local_218);
        }
        _write_string(&local_248,local_210,param_1,&local_218);
        if (((local_214 & 8) != 0) && ((local_214 & 4) == 0)) {
          _write_multi_char(0x30,local_288,param_1,&local_218);
        }
        if ((local_220 == 0) || ((int)local_240 < 1)) {
          _write_string((char *)local_224,(int)local_240,param_1,&local_218);
        }
        else {
          local_290 = local_224;
          local_28c = local_240;
          while (pcVar3 = local_28c + -1, bVar9 = local_28c != (char *)0x0, local_28c = pcVar3,
                bVar9) {
            sVar4 = *(short *)local_290;
            uVar6 = (uint)local_290 >> 0x10;
            local_290 = (uint *)((int)local_290 + 2);
            iVar8 = FUN_1000d3b0(local_294,CONCAT22((short)uVar6,sVar4));
            if (iVar8 < 1) break;
            _write_string(local_294,iVar8,param_1,&local_218);
          }
        }
        if ((local_214 & 4) != 0) {
          _write_multi_char(0x20,local_288,param_1,&local_218);
        }
      }
    }
  } while( true );
}



// Library Function - Single Match
//  _write_char
// 
// Library: Visual Studio 1998 Debug

void __cdecl _write_char(int param_1,FILE *param_2,int *param_3)

{
  uint local_8;
  
  param_2->_cnt = param_2->_cnt + -1;
  if (param_2->_cnt < 0) {
    local_8 = __flsbuf(param_1,param_2);
  }
  else {
    *param_2->_ptr = (char)param_1;
    local_8 = (uint)(byte)*param_2->_ptr;
    param_2->_ptr = param_2->_ptr + 1;
  }
  if (local_8 == 0xffffffff) {
    *param_3 = -1;
  }
  else {
    *param_3 = *param_3 + 1;
  }
  return;
}



// Library Function - Single Match
//  _write_multi_char
// 
// Library: Visual Studio 1998 Debug

void __cdecl _write_multi_char(int param_1,int param_2,FILE *param_3,int *param_4)

{
  do {
    if (param_2 < 1) {
      return;
    }
    _write_char(param_1,param_3,param_4);
    param_2 = param_2 + -1;
  } while (*param_4 != -1);
  return;
}



// Library Function - Single Match
//  _write_string
// 
// Library: Visual Studio 1998 Debug

void __cdecl _write_string(char *param_1,int param_2,FILE *param_3,int *param_4)

{
  do {
    if (param_2 < 1) {
      return;
    }
    _write_char((int)*param_1,param_3,param_4);
    param_1 = param_1 + 1;
    param_2 = param_2 + -1;
  } while (*param_4 != -1);
  return;
}



// Library Function - Single Match
//  _get_int_arg
// 
// Library: Visual Studio 1998 Debug

undefined4 __cdecl _get_int_arg(int *param_1)

{
  *param_1 = *param_1 + 4;
  return *(undefined4 *)(*param_1 + -4);
}



// Library Function - Single Match
//  _get_int64_arg
// 
// Library: Visual Studio 1998 Debug

undefined8 __cdecl _get_int64_arg(int *param_1)

{
  *param_1 = *param_1 + 8;
  return *(undefined8 *)(*param_1 + -8);
}



// Library Function - Single Match
//  _get_short_arg
// 
// Library: Visual Studio 1998 Debug

undefined4 __cdecl _get_short_arg(int *param_1)

{
  *param_1 = *param_1 + 4;
  return CONCAT22((short)((uint)*param_1 >> 0x10),*(undefined2 *)(*param_1 + -4));
}



// Library Function - Single Match
//  ___crtGetStringTypeW
// 
// Library: Visual Studio 1998 Debug

void __cdecl
___crtGetStringTypeW
          (DWORD param_1,LPCWSTR param_2,int param_3,LPWORD param_4,UINT param_5,LCID param_6)

{
  BOOL BVar1;
  int cbMultiByte;
  LPCSTR lpMultiByteStr;
  int iVar2;
  LPWORD local_c;
  WORD local_8 [2];
  
  if (DAT_10016654 == 0) {
    BVar1 = GetStringTypeW(1,(LPCWSTR)&lpSrcStr_1001666c,1,local_8);
    if (BVar1 == 0) {
      BVar1 = GetStringTypeA(0,1,(LPCSTR)&lpSrcStr_10016668,1,local_8);
      if (BVar1 == 0) {
        return;
      }
      DAT_10016654 = 2;
    }
    else {
      DAT_10016654 = 1;
    }
  }
  if (DAT_10016654 == 1) {
    GetStringTypeW(param_1,param_2,param_3,param_4);
  }
  else if (DAT_10016654 == 2) {
    local_c = (LPWORD)0x0;
    if (param_5 == 0) {
      param_5 = DAT_10016350;
    }
    cbMultiByte = WideCharToMultiByte(param_5,0x220,param_2,param_3,(LPSTR)0x0,0,(LPCSTR)0x0,
                                      (LPBOOL)0x0);
    if ((cbMultiByte != 0) &&
       (lpMultiByteStr = __calloc_dbg(1,cbMultiByte,2,s_aw_str_c_1001665c,0x76),
       lpMultiByteStr != (LPCSTR)0x0)) {
      iVar2 = WideCharToMultiByte(param_5,0x220,param_2,param_3,lpMultiByteStr,cbMultiByte,
                                  (LPCSTR)0x0,(LPBOOL)0x0);
      if ((iVar2 != 0) &&
         (local_c = (LPWORD)__malloc_dbg(cbMultiByte * 2 + 2,2,0x1001665c,0x80),
         local_c != (LPWORD)0x0)) {
        if (param_6 == 0) {
          param_6 = DAT_10016340;
        }
        local_c[param_3] = 0xffff;
        local_c[param_3 + -1] = local_c[param_3];
        GetStringTypeA(param_6,param_1,lpMultiByteStr,cbMultiByte,local_c);
        if ((local_c[param_3 + -1] != 0xffff) && (local_c[param_3] == 0xffff)) {
          FID_conflict__memcpy(param_4,local_c,param_3 * 2);
        }
      }
      __free_dbg(lpMultiByteStr,2);
      __free_dbg(local_c,2);
    }
  }
  return;
}



// Library Function - Single Match
//  ___crtGetStringTypeA
// 
// Library: Visual Studio 1998 Debug

BOOL __cdecl
___crtGetStringTypeA
          (_locale_t _Plocinfo,DWORD _DWInfoType,LPCSTR _LpSrcStr,int _CchSrc,LPWORD _LpCharType,
          int _Code_page,BOOL _BError)

{
  BOOL in_EAX;
  int iVar1;
  BOOL local_18;
  LPCWSTR local_c;
  WORD local_8 [2];
  
  local_18 = in_EAX;
  if (DAT_10016658 == 0) {
    local_18 = GetStringTypeA(0,1,(LPCSTR)&lpSrcStr_10016668,1,local_8);
    if (local_18 == 0) {
      local_18 = GetStringTypeW(1,(LPCWSTR)&lpSrcStr_1001666c,1,local_8);
      if (local_18 == 0) {
        return 0;
      }
      DAT_10016658 = 1;
    }
    else {
      DAT_10016658 = 2;
    }
  }
  if (DAT_10016658 == 2) {
    if (_Code_page == 0) {
      _Code_page = DAT_10016340;
    }
    local_18 = GetStringTypeA(_Code_page,(DWORD)_Plocinfo,(LPCSTR)_DWInfoType,(int)_LpSrcStr,
                              (LPWORD)_CchSrc);
  }
  else if (DAT_10016658 == 1) {
    local_18 = 0;
    local_c = (LPCWSTR)0x0;
    if (_LpCharType == (LPWORD)0x0) {
      _LpCharType = DAT_10016350;
    }
    iVar1 = MultiByteToWideChar((UINT)_LpCharType,9,(LPCSTR)_DWInfoType,(int)_LpSrcStr,(LPWSTR)0x0,0
                               );
    if (((iVar1 != 0) &&
        (local_c = (LPCWSTR)__calloc_dbg(2,iVar1,2,s_aw_str_c_1001665c,0x104),
        local_c != (LPCWSTR)0x0)) &&
       (iVar1 = MultiByteToWideChar((UINT)_LpCharType,1,(LPCSTR)_DWInfoType,(int)_LpSrcStr,local_c,
                                    iVar1), iVar1 != 0)) {
      local_18 = GetStringTypeW((DWORD)_Plocinfo,local_c,iVar1,(LPWORD)_CchSrc);
    }
    __free_dbg(local_c,2);
  }
  return local_18;
}



int FUN_1000c670(void)

{
  int iVar1;
  int local_c;
  int local_8;
  
  local_8 = 0;
  __lock(2);
  for (local_c = 3; local_c < DAT_1001828c; local_c = local_c + 1) {
    if (*(int *)(DAT_100185cc + local_c * 4) != 0) {
      if ((*(byte *)(*(int *)(DAT_100185cc + local_c * 4) + 0xc) & 0x83) != 0) {
        iVar1 = _fclose(*(FILE **)(DAT_100185cc + local_c * 4));
        if (iVar1 != -1) {
          local_8 = local_8 + 1;
        }
      }
      if (0x13 < local_c) {
        DeleteCriticalSection((LPCRITICAL_SECTION)(*(int *)(DAT_100185cc + local_c * 4) + 0x20));
        __free_dbg(*(void **)(DAT_100185cc + local_c * 4),2);
        *(undefined4 *)(DAT_100185cc + local_c * 4) = 0;
      }
    }
  }
  FUN_10005cb0(2);
  return local_8;
}



// Library Function - Single Match
//  _fflush
// 
// Library: Visual Studio 1998 Debug

int __cdecl _fflush(FILE *_File)

{
  int iVar1;
  
  if (_File == (FILE *)0x0) {
    iVar1 = FUN_1000c910(0);
  }
  else {
    FID_conflict___lock_file(_File);
    iVar1 = __fflush_lk(_File);
    FID_conflict___lock_file(_File);
  }
  return iVar1;
}



// Library Function - Single Match
//  __fflush_lk
// 
// Library: Visual Studio 1998 Debug

undefined4 __cdecl __fflush_lk(FILE *param_1)

{
  int iVar1;
  undefined4 uVar2;
  DWORD DVar3;
  
  iVar1 = __flush(param_1);
  if (iVar1 == 0) {
    if ((*(byte *)((int)&param_1->_flag + 1) & 0x40) == 0) {
      uVar2 = 0;
    }
    else {
      DVar3 = FUN_1000d720(param_1->_file);
      if (DVar3 == 0) {
        uVar2 = 0;
      }
      else {
        uVar2 = 0xffffffff;
      }
    }
  }
  else {
    uVar2 = 0xffffffff;
  }
  return uVar2;
}



// Library Function - Single Match
//  __flush
// 
// Library: Visual Studio 1998 Debug

int __cdecl __flush(FILE *_File)

{
  uint uVar1;
  uint uVar2;
  int local_10;
  
  local_10 = 0;
  if (((((byte)_File->_flag & 3) == 2) && ((_File->_flag & 0x108U) != 0)) &&
     (uVar1 = (int)_File->_ptr - (int)_File->_base, 0 < (int)uVar1)) {
    uVar2 = FUN_1000cd30(_File->_file,_File->_base,uVar1);
    if (uVar2 == uVar1) {
      if ((*(byte *)&_File->_flag & 0x80) != 0) {
        _File->_flag = _File->_flag & 0xfffffffd;
      }
    }
    else {
      _File->_flag = _File->_flag | 0x20;
      local_10 = -1;
    }
  }
  _File->_ptr = _File->_base;
  _File->_cnt = 0;
  return local_10;
}



// Library Function - Single Match
//  __flushall
// 
// Library: Visual Studio 1998 Debug

int __cdecl __flushall(void)

{
  int iVar1;
  
  iVar1 = FUN_1000c910(1);
  return iVar1;
}



int __cdecl FUN_1000c910(int param_1)

{
  int iVar1;
  int local_10;
  int local_c;
  int local_8;
  
  local_8 = 0;
  local_10 = 0;
  __lock(2);
  for (local_c = 0; local_c < 0x200; local_c = local_c + 1) {
    if ((*(int *)(DAT_100185cc + local_c * 4) != 0) &&
       ((*(byte *)(*(int *)(DAT_100185cc + local_c * 4) + 0xc) & 0x83) != 0)) {
      FUN_10005d30(local_c,*(int *)(DAT_100185cc + local_c * 4));
      if ((*(byte *)(*(int *)(DAT_100185cc + local_c * 4) + 0xc) & 0x83) != 0) {
        if (param_1 == 1) {
          iVar1 = __fflush_lk(*(FILE **)(DAT_100185cc + local_c * 4));
          if (iVar1 != -1) {
            local_8 = local_8 + 1;
          }
        }
        else if (((param_1 == 0) &&
                 ((*(byte *)(*(int *)(DAT_100185cc + local_c * 4) + 0xc) & 2) != 0)) &&
                (iVar1 = __fflush_lk(*(FILE **)(DAT_100185cc + local_c * 4)), iVar1 == -1)) {
          local_10 = -1;
        }
      }
      FUN_10005dd0(local_c,*(int *)(DAT_100185cc + local_c * 4));
    }
  }
  FUN_10005cb0(2);
  if (param_1 == 1) {
    local_10 = local_8;
  }
  return local_10;
}



// Library Function - Single Match
//  _abort
// 
// Library: Visual Studio 1998 Debug

void __cdecl _abort(void)

{
  FUN_10008a00(10);
  _raise(0x16);
  __exit(3);
  return;
}



char * __cdecl FUN_1000caa0(char *param_1,char *param_2,int param_3)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  bool bVar5;
  
  iVar2 = -1;
  pcVar4 = param_1;
  do {
    pcVar3 = pcVar4;
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    pcVar3 = pcVar4 + 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar3;
  } while (cVar1 != '\0');
  bVar5 = pcVar3 + -1 == (char *)0x0;
  iVar2 = param_3;
  pcVar4 = param_2;
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar5 = *pcVar4 == '\0';
    pcVar4 = pcVar4 + 1;
  } while (!bVar5);
  if (bVar5) {
    iVar2 = iVar2 + 1;
  }
  pcVar4 = pcVar3 + -1;
  for (iVar2 = -(iVar2 - param_3); iVar2 != 0; iVar2 = iVar2 + -1) {
    *pcVar4 = *param_2;
    param_2 = param_2 + 1;
    pcVar4 = pcVar4 + 1;
  }
  *pcVar4 = '\0';
  return param_1;
}



// Library Function - Multiple Matches With Different Base Names
//  _fprintf
//  _fwprintf
// 
// Library: Visual Studio 1998 Debug

int __cdecl FID_conflict__fwprintf(FILE *_File,wchar_t *_Format,...)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  if (_File == (FILE *)0x0) {
    uVar2 = FUN_10005fc0(2,s_fprintf_c_10016670,0x38,(uint *)0x0,s_str____NULL_1001660c);
    if (uVar2 == 1) {
      pcVar1 = (code *)swi(3);
      iVar3 = (*pcVar1)();
      return iVar3;
    }
  }
  if (_Format == (wchar_t *)0x0) {
    uVar2 = FUN_10005fc0(2,s_fprintf_c_10016670,0x39,(uint *)0x0,s_format____NULL_10015d74);
    if (uVar2 == 1) {
      pcVar1 = (code *)swi(3);
      iVar3 = (*pcVar1)();
      return iVar3;
    }
  }
  FID_conflict___lock_file(_File);
  iVar3 = __stbuf(_File);
  iVar4 = FUN_1000b1b0(_File,(byte *)_Format,(undefined4 *)&stack0x0000000c);
  __ftbuf(iVar3,_File);
  FID_conflict___lock_file(_File);
  return iVar4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _setvbuf
// 
// Library: Visual Studio 1998 Debug

int __cdecl _setvbuf(FILE *_File,char *_Buf,int _Mode,size_t _Size)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  int local_8;
  
  local_8 = 0;
  if ((_File == (FILE *)0x0) &&
     (uVar2 = FUN_10005fc0(2,s_setvbuf_c_1001667c,0x36,(uint *)0x0,s_str____NULL_1001660c),
     uVar2 == 1)) {
    pcVar1 = (code *)swi(3);
    iVar3 = (*pcVar1)();
    return iVar3;
  }
  if ((_Mode != 4) && (((_Size < 2 || (0x7fffffff < _Size)) || ((_Mode != 0 && (_Mode != 0x40))))))
  {
    return -1;
  }
  _Size = _Size & 0xfffffffe;
  FID_conflict___lock_file(_File);
  __flush(_File);
  __freebuf(_File);
  _File->_flag = _File->_flag & 0xffffc2f3;
  if ((_Mode & 4U) == 0) {
    if (_Buf == (char *)0x0) {
      _Buf = (char *)__malloc_dbg(_Size,2,0x1001667c,0x85);
      if (_Buf == (char *)0x0) {
        _DAT_10016238 = _DAT_10016238 + 1;
        local_8 = -1;
        goto LAB_1000cd0a;
      }
      _File->_flag = _File->_flag | 0x408;
    }
    else {
      _File->_flag = _File->_flag | 0x500;
    }
  }
  else {
    _File->_flag = _File->_flag | 4;
    _Buf = (char *)&_File->_charbuf;
    _Size = 2;
  }
  _File->_bufsiz = _Size;
  _File->_base = _Buf;
  _File->_ptr = _File->_base;
  _File->_cnt = 0;
LAB_1000cd0a:
  FID_conflict___lock_file(_File);
  return local_8;
}



int __cdecl FUN_1000cd30(uint param_1,char *param_2,uint param_3)

{
  int *piVar1;
  ulong *puVar2;
  int iVar3;
  
  if ((param_1 < DAT_100195d0) &&
     ((*(byte *)(*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0) >> 3)) + 4 +
                (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    __lock_fhandle(param_1);
    iVar3 = FUN_1000cde0(param_1,param_2,param_3);
    __unlock_fhandle(param_1);
  }
  else {
    piVar1 = FUN_1000aed0();
    *piVar1 = 9;
    puVar2 = FUN_1000aef0();
    *puVar2 = 0;
    iVar3 = -1;
  }
  return iVar3;
}



int __cdecl FUN_1000cde0(uint param_1,char *param_2,uint param_3)

{
  BOOL BVar1;
  int *piVar2;
  ulong *puVar3;
  DWORD local_424;
  int local_420;
  DWORD local_41c;
  char local_418;
  char local_414 [1028];
  DWORD local_10;
  char *local_c;
  char *local_8;
  
  local_10 = 0;
  local_420 = 0;
  if (param_3 == 0) {
    local_420 = 0;
  }
  else {
    if ((*(byte *)(*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0) >> 3)) + 4 +
                  (param_1 & 0x1f) * 0x24) & 0x20) != 0) {
      __lseek_lk(param_1,0,2);
    }
    if ((*(byte *)(*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0) >> 3)) + 4 +
                  (param_1 & 0x1f) * 0x24) & 0x80) == 0) {
      BVar1 = WriteFile(*(HANDLE *)
                         (*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0) >> 3)) +
                         (param_1 & 0x1f) * 0x24),param_2,param_3,&local_41c,(LPOVERLAPPED)0x0);
      if (BVar1 == 0) {
        local_424 = GetLastError();
      }
      else {
        local_424 = 0;
        local_10 = local_41c;
      }
    }
    else {
      local_8 = param_2;
      local_424 = 0;
      do {
        if (param_3 <= (uint)((int)local_8 - (int)param_2)) break;
        local_c = local_414;
        while (((int)local_c - (int)local_414 < 0x400 &&
               ((uint)((int)local_8 - (int)param_2) < param_3))) {
          local_418 = *local_8;
          local_8 = local_8 + 1;
          if (local_418 == '\n') {
            local_420 = local_420 + 1;
            *local_c = '\r';
            local_c = local_c + 1;
          }
          *local_c = local_418;
          local_c = local_c + 1;
        }
        BVar1 = WriteFile(*(HANDLE *)
                           (*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0) >> 3)) +
                           (param_1 & 0x1f) * 0x24),local_414,(int)local_c - (int)local_414,
                          &local_41c,(LPOVERLAPPED)0x0);
        if (BVar1 == 0) {
          local_424 = GetLastError();
          break;
        }
        local_10 = local_10 + local_41c;
      } while ((int)local_c - (int)local_414 <= (int)local_41c);
    }
    if (local_10 == 0) {
      if (local_424 == 0) {
        if (((*(byte *)(*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0) >> 3)) + 4 +
                       (param_1 & 0x1f) * 0x24) & 0x40) == 0) || (*param_2 != '\x1a')) {
          piVar2 = FUN_1000aed0();
          *piVar2 = 0x1c;
          puVar3 = FUN_1000aef0();
          *puVar3 = 0;
          local_420 = -1;
        }
        else {
          local_420 = 0;
        }
      }
      else {
        if (local_424 == 5) {
          piVar2 = FUN_1000aed0();
          *piVar2 = 9;
          puVar3 = FUN_1000aef0();
          *puVar3 = 5;
        }
        else {
          __dosmaperr(local_424);
        }
        local_420 = -1;
      }
    }
    else {
      local_420 = local_10 - local_420;
    }
  }
  return local_420;
}



// Library Function - Single Match
//  __lseek
// 
// Library: Visual Studio 1998 Debug

long __cdecl __lseek(int _FileHandle,long _Offset,int _Origin)

{
  int *piVar1;
  ulong *puVar2;
  DWORD DVar3;
  
  if (((uint)_FileHandle < DAT_100195d0) &&
     ((*(byte *)(*(int *)((int)&DAT_10019610 + ((int)(_FileHandle & 0xffffffe0U) >> 3)) + 4 +
                (_FileHandle & 0x1fU) * 0x24) & 1) != 0)) {
    __lock_fhandle(_FileHandle);
    DVar3 = __lseek_lk(_FileHandle,_Offset,_Origin);
    __unlock_fhandle(_FileHandle);
  }
  else {
    piVar1 = FUN_1000aed0();
    *piVar1 = 9;
    puVar2 = FUN_1000aef0();
    *puVar2 = 0;
    DVar3 = 0xffffffff;
  }
  return DVar3;
}



// Library Function - Single Match
//  __lseek_lk
// 
// Library: Visual Studio 1998 Debug

DWORD __cdecl __lseek_lk(uint param_1,LONG param_2,DWORD param_3)

{
  HANDLE hFile;
  int *piVar1;
  DWORD DVar2;
  DWORD local_10;
  
  hFile = (HANDLE)FUN_1000df00(param_1);
  if (hFile == (HANDLE)0xffffffff) {
    piVar1 = FUN_1000aed0();
    *piVar1 = 9;
    DVar2 = 0xffffffff;
  }
  else {
    DVar2 = SetFilePointer(hFile,param_2,(PLONG)0x0,param_3);
    if (DVar2 == 0xffffffff) {
      local_10 = GetLastError();
    }
    else {
      local_10 = 0;
    }
    if (local_10 == 0) {
      *(byte *)(*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0) >> 3)) + 4 +
               (param_1 & 0x1f) * 0x24) =
           *(byte *)(*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0) >> 3)) + 4 +
                    (param_1 & 0x1f) * 0x24) & 0xfd;
    }
    else {
      __dosmaperr(local_10);
      DVar2 = 0xffffffff;
    }
  }
  return DVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __getbuf
// 
// Library: Visual Studio 1998 Debug

void __cdecl __getbuf(FILE *_File)

{
  code *pcVar1;
  uint uVar2;
  char *pcVar3;
  
  if (_File == (FILE *)0x0) {
    uVar2 = FUN_10005fc0(2,s__getbuf_c_10016688,0x2e,(uint *)0x0,s_str____NULL_1001660c);
    if (uVar2 == 1) {
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
  }
  _DAT_10016238 = _DAT_10016238 + 1;
  pcVar3 = (char *)__malloc_dbg(0x1000,2,0x10016688,0x3b);
  _File->_base = pcVar3;
  if (_File->_base == (char *)0x0) {
    _File->_flag = _File->_flag | 4;
    _File->_base = (char *)&_File->_charbuf;
    _File->_bufsiz = 2;
  }
  else {
    _File->_flag = _File->_flag | 8;
    _File->_bufsiz = 0x1000;
  }
  _File->_ptr = _File->_base;
  _File->_cnt = 0;
  return;
}



// Library Function - Single Match
//  __isatty
// 
// Library: Visual Studio 1998 Debug

int __cdecl __isatty(int _FileHandle)

{
  uint uVar1;
  
  if ((uint)_FileHandle < DAT_100195d0) {
    uVar1 = (int)*(char *)(*(int *)((int)&DAT_10019610 + ((int)(_FileHandle & 0xffffffe0U) >> 3)) +
                           4 + (_FileHandle & 0x1fU) * 0x24) & 0x40;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



int __cdecl FUN_1000d3b0(LPSTR param_1,uint param_2)

{
  int iVar1;
  
  __lock(0x15);
  iVar1 = __wctomb_lk(param_1,param_2);
  FUN_10005cb0(0x15);
  return iVar1;
}



// Library Function - Single Match
//  __wctomb_lk
// 
// Library: Visual Studio 1998 Debug

int __cdecl __wctomb_lk(LPSTR param_1,uint param_2)

{
  int iVar1;
  int *piVar2;
  int local_8;
  
  if (param_1 == (LPSTR)0x0) {
    iVar1 = 0;
  }
  else if (DAT_10016340 == 0) {
    if ((param_2 & 0xffff) < 0x100) {
      *param_1 = (CHAR)param_2;
      iVar1 = 1;
    }
    else {
      piVar2 = FUN_1000aed0();
      *piVar2 = 0x2a;
      iVar1 = -1;
    }
  }
  else {
    local_8 = 0;
    iVar1 = WideCharToMultiByte(DAT_10016350,0x220,(LPCWSTR)&param_2,1,param_1,DAT_10015fac,
                                (LPCSTR)0x0,&local_8);
    if ((iVar1 == 0) || (local_8 != 0)) {
      piVar2 = FUN_1000aed0();
      *piVar2 = 0x2a;
      iVar1 = -1;
    }
  }
  return iVar1;
}



// Library Function - Single Match
//  __aulldiv
// 
// Library: Visual Studio

undefined8 __aulldiv(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  
  uVar3 = param_1;
  uVar8 = param_4;
  uVar6 = param_2;
  uVar9 = param_3;
  if (param_4 == 0) {
    uVar3 = param_2 / param_3;
    iVar4 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) /
                 (ulonglong)param_3);
  }
  else {
    do {
      uVar5 = uVar8 >> 1;
      uVar9 = uVar9 >> 1 | (uint)((uVar8 & 1) != 0) << 0x1f;
      uVar7 = uVar6 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar6 & 1) != 0) << 0x1f;
      uVar8 = uVar5;
      uVar6 = uVar7;
    } while (uVar5 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar9;
    iVar4 = (int)uVar1;
    lVar2 = (ulonglong)param_3 * (uVar1 & 0xffffffff);
    uVar3 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar8 = uVar3 + iVar4 * param_4;
    if (((CARRY4(uVar3,iVar4 * param_4)) || (param_2 < uVar8)) ||
       ((param_2 <= uVar8 && (param_1 < (uint)lVar2)))) {
      iVar4 = iVar4 + -1;
    }
    uVar3 = 0;
  }
  return CONCAT44(uVar3,iVar4);
}



// Library Function - Single Match
//  __aullrem
// 
// Library: Visual Studio

undefined8 __aullrem(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  bool bVar11;
  
  uVar3 = param_1;
  uVar4 = param_4;
  uVar9 = param_2;
  uVar10 = param_3;
  if (param_4 == 0) {
    iVar6 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) %
                 (ulonglong)param_3);
    iVar7 = 0;
  }
  else {
    do {
      uVar5 = uVar4 >> 1;
      uVar10 = uVar10 >> 1 | (uint)((uVar4 & 1) != 0) << 0x1f;
      uVar8 = uVar9 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar9 & 1) != 0) << 0x1f;
      uVar4 = uVar5;
      uVar9 = uVar8;
    } while (uVar5 != 0);
    uVar1 = CONCAT44(uVar8,uVar3) / (ulonglong)uVar10;
    uVar3 = (int)uVar1 * param_4;
    lVar2 = (uVar1 & 0xffffffff) * (ulonglong)param_3;
    uVar9 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar4 = (uint)lVar2;
    uVar10 = uVar9 + uVar3;
    if (((CARRY4(uVar9,uVar3)) || (param_2 < uVar10)) || ((param_2 <= uVar10 && (param_1 < uVar4))))
    {
      bVar11 = uVar4 < param_3;
      uVar4 = uVar4 - param_3;
      uVar10 = (uVar10 - param_4) - (uint)bVar11;
    }
    iVar6 = -(uVar4 - param_1);
    iVar7 = -(uint)(uVar4 - param_1 != 0) - ((uVar10 - param_2) - (uint)(uVar4 < param_1));
  }
  return CONCAT44(iVar7,iVar6);
}



// Library Function - Single Match
//  _fclose
// 
// Library: Visual Studio 1998 Debug

int __cdecl _fclose(FILE *_File)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  int local_8;
  
  local_8 = -1;
  if (_File == (FILE *)0x0) {
    uVar2 = FUN_10005fc0(2,s_fclose_c_100166b0,0x3a,(uint *)0x0,s_stream____NULL_100166bc);
    if (uVar2 == 1) {
      pcVar1 = (code *)swi(3);
      iVar3 = (*pcVar1)();
      return iVar3;
    }
  }
  if ((*(byte *)&_File->_flag & 0x40) == 0) {
    FID_conflict___lock_file(_File);
    local_8 = __fclose_lk(_File);
    FID_conflict___lock_file(_File);
  }
  else {
    _File->_flag = 0;
  }
  return local_8;
}



// Library Function - Single Match
//  __fclose_lk
// 
// Library: Visual Studio 1998 Debug

int __cdecl __fclose_lk(FILE *param_1)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  int local_c;
  
  local_c = -1;
  if (param_1 == (FILE *)0x0) {
    uVar2 = FUN_10005fc0(2,s_fclose_c_100166b0,0x77,(uint *)0x0,s_str____NULL_1001660c);
    if (uVar2 == 1) {
      pcVar1 = (code *)swi(3);
      iVar3 = (*pcVar1)();
      return iVar3;
    }
  }
  if ((*(byte *)&param_1->_flag & 0x83) != 0) {
    local_c = __flush(param_1);
    __freebuf(param_1);
    iVar3 = FUN_1000e1c0(param_1->_file);
    if (iVar3 < 0) {
      local_c = -1;
    }
    else if (param_1->_tmpfname != (char *)0x0) {
      __free_dbg(param_1->_tmpfname,2);
      param_1->_tmpfname = (char *)0x0;
    }
  }
  param_1->_flag = 0;
  return local_c;
}



DWORD __cdecl FUN_1000d720(uint param_1)

{
  int *piVar1;
  HANDLE hFile;
  BOOL BVar2;
  ulong *puVar3;
  DWORD local_8;
  
  if ((DAT_100195d0 <= param_1) ||
     ((*(byte *)(*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0) >> 3)) + 4 +
                (param_1 & 0x1f) * 0x24) & 1) == 0)) {
    piVar1 = FUN_1000aed0();
    *piVar1 = 9;
    return 0xffffffff;
  }
  __lock_fhandle(param_1);
  if ((*(byte *)(*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0) >> 3)) + 4 +
                (param_1 & 0x1f) * 0x24) & 1) != 0) {
    hFile = (HANDLE)FUN_1000df00(param_1);
    BVar2 = FlushFileBuffers(hFile);
    if (BVar2 == 0) {
      local_8 = GetLastError();
    }
    else {
      local_8 = 0;
    }
    if (local_8 == 0) goto LAB_1000d81f;
    puVar3 = FUN_1000aef0();
    *puVar3 = local_8;
  }
  piVar1 = FUN_1000aed0();
  *piVar1 = 9;
  local_8 = 0xffffffff;
LAB_1000d81f:
  __unlock_fhandle(param_1);
  return local_8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __stbuf
// 
// Library: Visual Studio 1998 Debug

int __cdecl __stbuf(FILE *_File)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  int local_c;
  
  if ((_File == (FILE *)0x0) &&
     (uVar2 = FUN_10005fc0(2,s__sftbuf_c_100166d8,0x41,(uint *)0x0,s_str____NULL_1001660c),
     uVar2 == 1)) {
    pcVar1 = (code *)swi(3);
    iVar3 = (*pcVar1)();
    return iVar3;
  }
  iVar3 = __isatty(_File->_file);
  if (iVar3 == 0) {
    iVar3 = 0;
  }
  else {
    if (_File == (FILE *)0x10015fd8) {
      local_c = 0;
    }
    else {
      if (_File != (FILE *)&DAT_10015ff8) {
        return 0;
      }
      local_c = 1;
    }
    _DAT_10016238 = _DAT_10016238 + 1;
    if ((_File->_flag & 0x10cU) == 0) {
      if (*(int *)(&DAT_100166d0 + local_c * 4) == 0) {
        uVar4 = __malloc_dbg(0x1000,2,0x100166d8,0x5e);
        *(undefined4 *)(&DAT_100166d0 + local_c * 4) = uVar4;
        if (*(int *)(&DAT_100166d0 + local_c * 4) == 0) {
          return 0;
        }
      }
      _File->_base = *(char **)(&DAT_100166d0 + local_c * 4);
      _File->_ptr = _File->_base;
      _File->_bufsiz = 0x1000;
      _File->_cnt = _File->_bufsiz;
      _File->_flag = _File->_flag | 0x1102;
      iVar3 = 1;
    }
    else {
      iVar3 = 0;
    }
  }
  return iVar3;
}



// Library Function - Single Match
//  __ftbuf
// 
// Library: Visual Studio 1998 Debug

void __cdecl __ftbuf(int _Flag,FILE *_File)

{
  code *pcVar1;
  uint uVar2;
  
  if ((_Flag != 0) && (_Flag != 1)) {
    uVar2 = FUN_10005fc0(2,s__sftbuf_c_100166d8,0x96,(uint *)0x0,s_flag____0____flag____1_100166e4);
    if (uVar2 == 1) {
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
  }
  if ((_Flag != 0) && ((*(byte *)((int)&_File->_flag + 1) & 0x10) != 0)) {
    __flush(_File);
    _File->_flag = _File->_flag & 0xffffeeff;
    _File->_bufsiz = 0;
    _File->_ptr = (char *)0x0;
    _File->_base = _File->_ptr;
  }
  return;
}



// Library Function - Single Match
//  __freebuf
// 
// Library: Visual Studio 1998 Debug

void __cdecl __freebuf(FILE *_File)

{
  code *pcVar1;
  uint uVar2;
  
  if (_File == (FILE *)0x0) {
    uVar2 = FUN_10005fc0(2,s__freebuf_c_100166fc,0x30,(uint *)0x0,s_stream____NULL_100166bc);
    if (uVar2 == 1) {
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
  }
  if (((*(byte *)&_File->_flag & 0x83) != 0) && ((*(byte *)&_File->_flag & 8) != 0)) {
    __free_dbg(_File->_base,2);
    _File->_flag = _File->_flag & 0xfffffbf7;
    _File->_ptr = (char *)0x0;
    _File->_base = _File->_ptr;
    _File->_cnt = 0;
  }
  return;
}



int FUN_1000dac0(void)

{
  int local_10;
  undefined4 *local_c;
  int local_8;
  
  local_8 = -1;
  __lock(0x12);
  local_10 = 0;
  do {
    if (0x3f < local_10) {
LAB_1000dc94:
      FUN_10005cb0(0x12);
      return local_8;
    }
    if ((&DAT_10019610)[local_10] == 0) {
      local_c = (undefined4 *)__malloc_dbg(0x480,2,0x10016708,0x79);
      if (local_c != (undefined4 *)0x0) {
        (&DAT_10019610)[local_10] = local_c;
        DAT_100195d0 = DAT_100195d0 + 0x20;
        for (; local_c < (undefined4 *)((&DAT_10019610)[local_10] + 0x480); local_c = local_c + 9) {
          *(undefined *)(local_c + 1) = 0;
          *local_c = 0xffffffff;
          *(undefined *)((int)local_c + 5) = 10;
          local_c[2] = 0;
        }
        __lock_fhandle(local_10);
        local_8 = local_10 << 5;
      }
      goto LAB_1000dc94;
    }
    for (local_c = (undefined4 *)(&DAT_10019610)[local_10];
        local_c < (undefined4 *)((&DAT_10019610)[local_10] + 0x480); local_c = local_c + 9) {
      if ((*(byte *)(local_c + 1) & 1) == 0) {
        if (local_c[2] == 0) {
          __lock(0x11);
          if (local_c[2] == 0) {
            InitializeCriticalSection((LPCRITICAL_SECTION)(local_c + 3));
            local_c[2] = local_c[2] + 1;
          }
          FUN_10005cb0(0x11);
        }
        EnterCriticalSection((LPCRITICAL_SECTION)(local_c + 3));
        if ((*(byte *)(local_c + 1) & 1) == 0) {
          *local_c = 0xffffffff;
          local_8 = ((int)local_c - (&DAT_10019610)[local_10]) / 0x24 + local_10 * 0x20;
          break;
        }
        LeaveCriticalSection((LPCRITICAL_SECTION)(local_c + 3));
      }
    }
    if (local_8 != -1) goto LAB_1000dc94;
    local_10 = local_10 + 1;
  } while( true );
}



// Library Function - Single Match
//  __set_osfhnd
// 
// Library: Visual Studio 1998 Debug

int __cdecl __set_osfhnd(int param_1,intptr_t param_2)

{
  int iVar1;
  int *piVar2;
  ulong *puVar3;
  
  if (((uint)param_1 < DAT_100195d0) &&
     (*(int *)(*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0U) >> 3)) +
              (param_1 & 0x1fU) * 0x24) == -1)) {
    if (DAT_10014cc4 == 1) {
      if (param_1 == 0) {
        SetStdHandle(0xfffffff6,(HANDLE)param_2);
      }
      else if (param_1 == 1) {
        SetStdHandle(0xfffffff5,(HANDLE)param_2);
      }
      else if (param_1 == 2) {
        SetStdHandle(0xfffffff4,(HANDLE)param_2);
      }
    }
    *(intptr_t *)
     (*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0U) >> 3)) + (param_1 & 0x1fU) * 0x24)
         = param_2;
    iVar1 = 0;
  }
  else {
    piVar2 = FUN_1000aed0();
    *piVar2 = 9;
    puVar3 = FUN_1000aef0();
    *puVar3 = 0;
    iVar1 = -1;
  }
  return iVar1;
}



undefined4 __cdecl FUN_1000ddc0(uint param_1)

{
  undefined4 uVar1;
  int *piVar2;
  ulong *puVar3;
  
  if (((param_1 < DAT_100195d0) &&
      ((*(byte *)(*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0) >> 3)) + 4 +
                 (param_1 & 0x1f) * 0x24) & 1) != 0)) &&
     (*(int *)(*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0) >> 3)) +
              (param_1 & 0x1f) * 0x24) != -1)) {
    if (DAT_10014cc4 == 1) {
      if (param_1 == 0) {
        SetStdHandle(0xfffffff6,(HANDLE)0x0);
      }
      else if (param_1 == 1) {
        SetStdHandle(0xfffffff5,(HANDLE)0x0);
      }
      else if (param_1 == 2) {
        SetStdHandle(0xfffffff4,(HANDLE)0x0);
      }
    }
    *(undefined4 *)
     (*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0) >> 3)) + (param_1 & 0x1f) * 0x24) =
         0xffffffff;
    uVar1 = 0;
  }
  else {
    piVar2 = FUN_1000aed0();
    *piVar2 = 9;
    puVar3 = FUN_1000aef0();
    *puVar3 = 0;
    uVar1 = 0xffffffff;
  }
  return uVar1;
}



undefined4 __cdecl FUN_1000df00(uint param_1)

{
  int *piVar1;
  ulong *puVar2;
  undefined4 uVar3;
  
  if ((param_1 < DAT_100195d0) &&
     ((*(byte *)(*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0) >> 3)) + 4 +
                (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    uVar3 = *(undefined4 *)
             (*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0) >> 3)) +
             (param_1 & 0x1f) * 0x24);
  }
  else {
    piVar1 = FUN_1000aed0();
    *piVar1 = 9;
    puVar2 = FUN_1000aef0();
    *puVar2 = 0;
    uVar3 = 0xffffffff;
  }
  return uVar3;
}



// Library Function - Single Match
//  __open_osfhandle
// 
// Library: Visual Studio 1998 Debug

int __cdecl __open_osfhandle(intptr_t _OSFileHandle,int _Flags)

{
  DWORD DVar1;
  uint _Filehandle;
  int *piVar2;
  ulong *puVar3;
  byte local_10;
  
  local_10 = 0;
  if ((_Flags & 8U) != 0) {
    local_10 = 0x20;
  }
  if ((_Flags & 0x4000U) != 0) {
    local_10 = local_10 | 0x80;
  }
  DVar1 = GetFileType((HANDLE)_OSFileHandle);
  if (DVar1 == 0) {
    DVar1 = GetLastError();
    __dosmaperr(DVar1);
    _Filehandle = 0xffffffff;
  }
  else {
    if (DVar1 == 2) {
      local_10 = local_10 | 0x40;
    }
    else if (DVar1 == 3) {
      local_10 = local_10 | 8;
    }
    _Filehandle = FUN_1000dac0();
    if (_Filehandle == 0xffffffff) {
      piVar2 = FUN_1000aed0();
      *piVar2 = 0x18;
      puVar3 = FUN_1000aef0();
      *puVar3 = 0;
      _Filehandle = 0xffffffff;
    }
    else {
      __set_osfhnd(_Filehandle,_OSFileHandle);
      *(byte *)(*(int *)((int)&DAT_10019610 + ((int)(_Filehandle & 0xffffffe0) >> 3)) + 4 +
               (_Filehandle & 0x1f) * 0x24) = local_10 | 1;
      __unlock_fhandle(_Filehandle);
    }
  }
  return _Filehandle;
}



// Library Function - Single Match
//  __lock_fhandle
// 
// Library: Visual Studio 1998 Debug

int __cdecl __lock_fhandle(int _Filehandle)

{
  int iVar1;
  int extraout_EAX;
  
  iVar1 = *(int *)((int)&DAT_10019610 + ((int)(_Filehandle & 0xffffffe0U) >> 3)) +
          (_Filehandle & 0x1fU) * 0x24;
  if (*(int *)(iVar1 + 8) == 0) {
    __lock(0x11);
    if (*(int *)(iVar1 + 8) == 0) {
      InitializeCriticalSection((LPCRITICAL_SECTION)(iVar1 + 0xc));
      *(int *)(iVar1 + 8) = *(int *)(iVar1 + 8) + 1;
    }
    FUN_10005cb0(0x11);
  }
  EnterCriticalSection
            ((LPCRITICAL_SECTION)
             (*(int *)((int)&DAT_10019610 + ((int)(_Filehandle & 0xffffffe0U) >> 3)) +
              (_Filehandle & 0x1fU) * 0x24 + 0xc));
  return extraout_EAX;
}



// Library Function - Single Match
//  __unlock_fhandle
// 
// Library: Visual Studio 1998 Debug

void __cdecl __unlock_fhandle(int _Filehandle)

{
  LeaveCriticalSection
            ((LPCRITICAL_SECTION)
             (*(int *)((int)&DAT_10019610 + ((int)(_Filehandle & 0xffffffe0U) >> 3)) +
              (_Filehandle & 0x1fU) * 0x24 + 0xc));
  return;
}



// Library Function - Single Match
//  __fptrap
// 
// Library: Visual Studio 1998 Debug

void __cdecl __fptrap(void)

{
  __amsg_exit(2);
  return;
}



undefined4 __cdecl FUN_1000e1c0(uint param_1)

{
  int *piVar1;
  ulong *puVar2;
  undefined4 uVar3;
  
  if ((param_1 < DAT_100195d0) &&
     ((*(byte *)(*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0) >> 3)) + 4 +
                (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    __lock_fhandle(param_1);
    uVar3 = __close_lk(param_1);
    __unlock_fhandle(param_1);
  }
  else {
    piVar1 = FUN_1000aed0();
    *piVar1 = 9;
    puVar2 = FUN_1000aef0();
    *puVar2 = 0;
    uVar3 = 0xffffffff;
  }
  return uVar3;
}



// Library Function - Single Match
//  __close_lk
// 
// Library: Visual Studio 1998 Debug

undefined4 __cdecl __close_lk(uint param_1)

{
  int iVar1;
  int iVar2;
  HANDLE hObject;
  BOOL BVar3;
  undefined4 uVar4;
  DWORD local_8;
  
  if ((param_1 == 1) || (param_1 == 2)) {
    iVar1 = FUN_1000df00(2);
    iVar2 = FUN_1000df00(1);
    if (iVar1 != iVar2) goto LAB_1000e29b;
  }
  else {
LAB_1000e29b:
    hObject = (HANDLE)FUN_1000df00(param_1);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      local_8 = GetLastError();
      goto LAB_1000e2cb;
    }
  }
  local_8 = 0;
LAB_1000e2cb:
  FUN_1000ddc0(param_1);
  if (local_8 == 0) {
    *(undefined *)
     (*(int *)((int)&DAT_10019610 + ((int)(param_1 & 0xffffffe0) >> 3)) + 4 +
     (param_1 & 0x1f) * 0x24) = 0;
    uVar4 = 0;
  }
  else {
    __dosmaperr(local_8);
    uVar4 = 0xffffffff;
  }
  return uVar4;
}



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x1000e324. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}


