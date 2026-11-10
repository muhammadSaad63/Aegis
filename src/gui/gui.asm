; Aegis GUI: a Win32 dialog front end for the ciphers of main.asm (the cipher procedures below are copied from main.asm as is)
; build it with build.bat from a Visual Studio x86 developer command prompt

.386
.model flat, stdcall
OPTION CASEMAP:NONE

includelib kernel32.lib
includelib user32.lib
includelib comdlg32.lib

; windows api prototypes
ExitProcess         PROTO :DWORD
GetModuleHandleA    PROTO :DWORD
CreateFileA         PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ReadFile            PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
WriteFile           PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CloseHandle         PROTO :DWORD
DialogBoxParamA     PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
EndDialog           PROTO :DWORD, :DWORD
GetDlgItem          PROTO :DWORD, :DWORD
GetDlgItemTextA     PROTO :DWORD, :DWORD, :DWORD, :DWORD
SetDlgItemTextA     PROTO :DWORD, :DWORD, :DWORD
SendDlgItemMessageA PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CheckRadioButton    PROTO :DWORD, :DWORD, :DWORD, :DWORD
CheckDlgButton      PROTO :DWORD, :DWORD, :DWORD
IsDlgButtonChecked  PROTO :DWORD, :DWORD
EnableWindow        PROTO :DWORD, :DWORD
MessageBoxA         PROTO :DWORD, :DWORD, :DWORD, :DWORD
GetOpenFileNameA    PROTO :DWORD
GetSaveFileNameA    PROTO :DWORD

; open/save dialog structure
OPENFILENAME STRUCT
    lStructSize       DWORD ?
    hwndOwner         DWORD ?
    hInstance         DWORD ?
    lpstrFilter       DWORD ?
    lpstrCustomFilter DWORD ?
    nMaxCustFilter    DWORD ?
    nFilterIndex      DWORD ?
    lpstrFile         DWORD ?
    nMaxFile          DWORD ?
    lpstrFileTitle    DWORD ?
    nMaxFileTitle     DWORD ?
    lpstrInitialDir   DWORD ?
    lpstrTitle        DWORD ?
    Flags             DWORD ?
    nFileOffset       WORD  ?
    nFileExtension    WORD  ?
    lpstrDefExt       DWORD ?
    lCustData         DWORD ?
    lpfnHook          DWORD ?
    lpTemplateName    DWORD ?
OPENFILENAME ENDS

; constants
SMALL_SIZE  = 64
MEDIUM_SIZE = 256
LARGE_SIZE  = 4096
HEX_SIZE    = 8192                      ; twice LARGE_SIZE since every byte becomes 2 hex digits

; windows constants
WM_INITDIALOG       = 110h
WM_COMMAND          = 111h
WM_CLOSE            = 10h
IDCANCEL            = 2
CB_ADDSTRING        = 143h
CB_GETCURSEL        = 147h
CB_SETCURSEL        = 14Eh
MB_ICONERROR        = 10h
GENERIC_READ        = 80000000h
GENERIC_WRITE       = 40000000h
FILE_SHARE_READ     = 1
CREATE_ALWAYS       = 2
OPEN_EXISTING       = 3
FILE_ATTRIBUTE_NORMAL = 80h
INVALID_HANDLE_VALUE  = -1
OFN_HIDEREADONLY    = 4
OFN_OVERWRITEPROMPT = 2
OFN_PATHMUSTEXIST   = 800h
OFN_FILEMUSTEXIST   = 1000h

; dialog ids (must match gui.rc)
IDD_MAIN      = 100
IDC_CIPHER    = 1001
IDC_ENCRYPT   = 1002
IDC_DECRYPT   = 1003
IDC_TEXT      = 1004
IDC_FILE      = 1005
IDC_HEX       = 1006
IDC_KEY       = 1007
IDC_INPATH    = 1008
IDC_BROWSEIN  = 1009
IDC_OUTPATH   = 1010
IDC_BROWSEOUT = 1011
IDC_TEXTIN    = 1012
IDC_TEXTOUT   = 1013
IDC_STATUS    = 1014
IDC_RUN       = 1015

; variables
.data
    ; data buffers
    bytesRead      DWORD ?
    bytesWritten   DWORD ?
    inputHandle    DWORD ?
    outputHandle   DWORD ?

    ; string buffers
    keyBuffer      BYTE SMALL_SIZE  DUP(?)
    dataBuffer     BYTE LARGE_SIZE  DUP(?)
    inputFilePath  BYTE MEDIUM_SIZE DUP(?)
    outputFilePath BYTE MEDIUM_SIZE DUP(?)
    hexBuffer      BYTE HEX_SIZE    DUP(?)

    ; message strings
    errOpenMsg      BYTE "Error: Failed to open or create file.", 0
    errIOMsg        BYTE "Error: Failed to read from or write to file.", 0
    errHexMsg       BYTE "Error: The text is not valid hex (pairs of 0-9 / A-F).", 0
    emptyInputMsg   BYTE "Error: Input path, text or key cannot be empty.", 0
    successMsg      BYTE "Success!", 0
    emptyStatus     BYTE 0
    captionError    BYTE "Aegis - Error", 0

    ; cipher names shown in the dropdown
    cipherName1     BYTE "[1] XOR Cipher", 0
    cipherName2     BYTE "[2] Caesar Cipher", 0
    cipherName3     BYTE "[3] Rail Fence", 0
    cipherName4     BYTE "[4] Vigenere Cipher", 0
    cipherName5     BYTE "[5] RC4", 0

    ; open/save dialog data
    filterAll       BYTE "All Files (*.*)", 0, "*.*", 0, 0
    ofn             OPENFILENAME <>
    hexDigits       BYTE "0123456789ABCDEF"

    ; arr of procedure pointers
    encryptionCiphers DWORD OFFSET encrypt_XORCipher,
                            OFFSET encrypt_CaesarCipher,
                            OFFSET encrypt_RailFenceCipher,
                            OFFSET encrypt_VigenereCipher,
                            OFFSET encrypt_RC4Cipher

    decryptionCiphers DWORD OFFSET decrypt_XORCipher,
                            OFFSET decrypt_CaesarCipher,
                            OFFSET decrypt_RailFenceCipher,
                            OFFSET decrypt_VigenereCipher,
                            OFFSET decrypt_RC4Cipher

    ; control flags
    isModeEncryption  BYTE  1               ; 0: decryption, 1: encryption  | initially set for encryption
    isHexText         BYTE  1               ; 0: raw text, 1: text is shown as hex
    activeCipherIndex DWORD 0

    tempBuffer       BYTE LARGE_SIZE DUP(?)
    rc4State         BYTE 256 DUP(?)

.code

    ; dynamically chooses the enc/dec algo to use based upon userChoice
    dispatchCipher PROC

        MOV eax, activeCipherIndex

        ; Check whether we are in Encryption or Decryption mode
            CMP isModeEncryption, 1
            JE  dispatchEncryption

        dispatchDecryption:
            CALL decryptionCiphers[eax * TYPE decryptionCiphers]
            RET

        dispatchEncryption:
            CALL encryptionCiphers[eax * TYPE encryptionCiphers]
            RET

    dispatchCipher ENDP
    ; performs the very basic XOR cipher on the data chunk
    encrypt_XORCipher PROC

        initializeRegs:
            MOV esi, OFFSET dataBuffer      ; holds address of data chunk
            MOV ecx, bytesRead              ; loop counter
            XOR edi, edi                    ; effectively MOV edi, 0

        getCipherKey:
            MOV al, keyBuffer[edi]          ; get current key byte
            CMP al, 0                       ; checks for null terminator of key string
            JNE applyCipher                 ; if al != 0 (ie the null terminator), jumnp to applyXOR
            XOR edi, edi                    ; reset key index (wrap around) if null terminator reached
            MOV al, keyBuffer[edi]          ; get value at start of key

        applyCipher:   
            XOR [esi], al                   ; apply bitwise xor to a byte of the data chunk
            INC esi                         ; move to next data byte
            INC edi                         ; move to next key byte

            LOOP getCipherKey               ; decrements ecx and then gets the next key if ecx != 0

        RET

    encrypt_XORCipher ENDP


    ; decryption algo for the XOR cipher
    decrypt_XORCipher PROC

        initializeRegs:
            MOV esi, OFFSET dataBuffer      ; holds address of data chunk
            MOV ecx, bytesRead              ; loop counter
            XOR edi, edi                    ; effectively MOV edi, 0

        getCipherKey:
            MOV al, keyBuffer[edi]          ; get current key byte
            CMP al, 0                       ; checks for null terminator of key string
            JNE applyCipher                 ; if al != 0, jump to applyCipher
            XOR edi, edi                    ; reset key index (wrap around)
            MOV al, keyBuffer[edi]          ; get value at start of key

        applyCipher:   
            XOR [esi], al                   ; apply bitwise xor to undo encryption
            INC esi                         ; move to next data byte
            INC edi                         ; move to next key byte
            LOOP getCipherKey

        RET

    decrypt_XORCipher ENDP


    ; a very basic cipher which encrypts by shifting each char in the text forward (by ascii) by some key amount
    encrypt_CaesarCipher PROC

        initializeRegs:
                MOV esi, OFFSET dataBuffer                            ; points to source data chunk
                MOV ecx, bytesRead                                    ; the loop counter = bytes actually read
                MOV bl, 3                                             ; using a arbitrary shift of 3 for now

        applyCipher:
            MOV al, [esi]                                             ; Load current byte

            checkUpperCase:
                ; check if byte is uppercase (A-Z -> ascii 65 to 90)
                    CMP al, 'A'
                    JB  skipByte                                      ; skip the byte if its ascii value is below A (ie it aint a alphabet)
                    CMP al, 'Z'
                    JA  checkLowerCase                                ; if the byte is greater than Z, go check if it is lowercase
                
                ; handle uppercase shift with wrapAround
                    ADD al, bl                                        ; apply shift
                    CMP al, 'Z'                                       
                    JBE storeByte                                     ; stores the byte if it below or eual to Z
                    SUB al, 26                                        ; wrap around if past Z
                    JMP storeByte

            checkLowerCase:
                ; check if byte is lowercased (a-z -> ascii 97 to 122)
                    CMP al, 'a'
                    JB  skipByte                                      ; skips if ascii value of byte is > Z & < a (ie bw Z and a)
                    CMP al, 'z'
                    JA  skipByte                                      ; skips if ascii value of byte is > a (ie > 122)

                ; handle lowerCase shift with wrapAround
                    ADD al, bl                                        ; apply shift
                    CMP al, 'z'
                    JBE storeByte
                    SUB al, 26                                        ; wrap around if past z
                    JMP storeByte  

            storeByte:
                MOV [esi], al                                         ; saves transformed byte back inPlace

        skipByte:
            INC  esi                                                   ; move to next byte of dataBuffer
            LOOP applyCipher

        RET

    encrypt_CaesarCipher ENDP


    ; the decryption algo for the caesar cipher which decrypts by subtracting the key from the text instead of adding it
    decrypt_CaesarCipher PROC

        initializeRegs:
            MOV esi, OFFSET dataBuffer                            ; points to source data chunk
            MOV ecx, bytesRead                                    ; the loop counter = bytes actually read
            MOV bl, 3                                             ; shift of 3 used in encryption

        applyCipher:
            MOV al, [esi]                                         ; Load current byte

            checkUpperCase:
                ; check if byte is uppercase (A-Z -> ascii 65 to 90)
                CMP al, 'A'
                JB  skipByte                                      ; skip if below 'A'
                CMP al, 'Z'
                JA  checkLowerCase                                ; if above 'Z', check lowercase

                ; handle uppercase reverse shift with wrapAround
                SUB al, bl                                        ; subtract shift
                CMP al, 'A'                                       
                JAE storeByte                                     ; stores if greater than or equal to 'A'
                ADD al, 26                                        ; wrap around if past 'A' downwards
                JMP storeByte

            checkLowerCase:
                ; check if byte is lowercase (a-z -> ascii 97 to 122)
                CMP al, 'a'
                JB  skipByte                                      ; skip if between 'Z' and 'a'
                CMP al, 'z'
                JA  skipByte                                      ; skip if above 'z'

                ; handle lowercase reverse shift with wrapAround
                SUB al, bl                                        ; subtract shift
                CMP al, 'a'
                JAE storeByte
                ADD al, 26                                        ; wrap around if past 'a' downwards
                JMP storeByte  

            storeByte:
                MOV [esi], al                                     ; saves transformed byte back in-place

        skipByte:
            INC  esi                                              ; move to next byte of dataBuffer
            LOOP applyCipher

        RET

    decrypt_CaesarCipher ENDP


    ; easy
    encrypt_RailFenceCipher PROC

        MOV esi, OFFSET dataBuffer
        MOV edi, OFFSET tempBuffer
        MOV ebx, bytesRead
        XOR eax, eax

        rfEvenLoop:
            CMP eax, ebx
            JAE rfOddStart

            MOV dl, [esi + eax]
            MOV [edi], dl
            INC edi
            ADD eax, 2
            JMP rfEvenLoop

        rfOddStart:
            MOV eax, 1

        rfOddLoop:
            CMP eax, ebx
            JAE rfCopyBack

            MOV dl, [esi + eax]
            MOV [edi], dl
            INC edi
            ADD eax, 2
            JMP rfOddLoop

        rfCopyBack:
            MOV esi, OFFSET tempBuffer
            MOV edi, OFFSET dataBuffer
            MOV ecx, bytesRead

        rfCopyLoop:
            MOV al, [esi]
            MOV [edi], al
            INC esi
            INC edi
            LOOP rfCopyLoop

        RET

    encrypt_RailFenceCipher ENDP


    decrypt_RailFenceCipher PROC

        MOV esi, OFFSET dataBuffer
        MOV eax, bytesRead
        INC eax
        SHR eax, 1

        MOV edi, OFFSET dataBuffer
        ADD edi, eax

        MOV edx, OFFSET tempBuffer
        MOV ecx, bytesRead
        XOR ebx, ebx

        rfDecLoop:
            CMP ebx, 0
            JNE rfSecondRail

            MOV al, [esi]
            INC esi
            JMP rfStoreChar

        rfSecondRail:
            MOV al, [edi]
            INC edi

        rfStoreChar:
            MOV [edx], al
            INC edx
            XOR ebx, 1
            LOOP rfDecLoop

        MOV esi, OFFSET tempBuffer
        MOV edi, OFFSET dataBuffer
        MOV ecx, bytesRead

        rfDecCopy:
            MOV al, [esi]
            MOV [edi], al
            INC esi
            INC edi
            LOOP rfDecCopy

        RET

    decrypt_RailFenceCipher ENDP


    ; folds the key shift in dl into the range 0 - 25 (a non-alphabetic key char would otherwise give an invalid, non-reversible shift)
    foldVigenereShift PROC

        foldLoop:
            CMP dl, 26
            JB  foldDone
            SUB dl, 26
            JMP foldLoop

        foldDone:
            RET

    foldVigenereShift ENDP


    ; easy - medium
    encrypt_VigenereCipher PROC

        MOV esi, OFFSET dataBuffer
        MOV edi, 0
        MOV ecx, bytesRead

        vigEncLoop:
            MOV al, [esi]

            CMP al, 'A'
            JB vigEncNext
            CMP al, 'Z'
            JBE vigEncUpper

            CMP al, 'a'
            JB vigEncNext
            CMP al, 'z'
            JA vigEncNext

            MOV dl, keyBuffer[edi]
            CMP dl, 'a'
            JB vigEncLowerKey
            SUB dl, 'a'
            JMP vigEncLower

        vigEncLowerKey:
            SUB dl, 'A'

        vigEncLower:
            CALL foldVigenereShift
            ADD al, dl
            CMP al, 'z'
            JBE vigEncStore
            SUB al, 26
            JMP vigEncStore

        vigEncUpper:
            MOV dl, keyBuffer[edi]
            CMP dl, 'a'
            JB vigEncUpperKey
            SUB dl, 'a'
            JMP vigEncUpperApply

        vigEncUpperKey:
            SUB dl, 'A'

        vigEncUpperApply:
            CALL foldVigenereShift
            ADD al, dl
            CMP al, 'Z'
            JBE vigEncStore
            SUB al, 26

        vigEncStore:
            MOV [esi], al
            INC edi

            CMP keyBuffer[edi], 0
            JNE vigEncNext
            XOR edi, edi

        vigEncNext:
            INC esi
            LOOP vigEncLoop

        RET

    encrypt_VigenereCipher ENDP


    decrypt_VigenereCipher PROC

        MOV esi, OFFSET dataBuffer
        MOV edi, 0
        MOV ecx, bytesRead

        vigDecLoop:
            MOV al, [esi]

            CMP al, 'A'
            JB vigDecNext
            CMP al, 'Z'
            JBE vigDecUpper

            CMP al, 'a'
            JB vigDecNext
            CMP al, 'z'
            JA vigDecNext

            MOV dl, keyBuffer[edi]
            CMP dl, 'a'
            JB vigDecLowerKey
            SUB dl, 'a'
            JMP vigDecLower

        vigDecLowerKey:
            SUB dl, 'A'

        vigDecLower:
            CALL foldVigenereShift
            SUB al, dl
            CMP al, 'a'
            JAE vigDecStore
            ADD al, 26
            JMP vigDecStore

        vigDecUpper:
            MOV dl, keyBuffer[edi]
            CMP dl, 'a'
            JB vigDecUpperKey
            SUB dl, 'a'
            JMP vigDecUpperApply

        vigDecUpperKey:
            SUB dl, 'A'

        vigDecUpperApply:
            CALL foldVigenereShift
            SUB al, dl
            CMP al, 'A'
            JAE vigDecStore
            ADD al, 26

        vigDecStore:
            MOV [esi], al
            INC edi

            CMP keyBuffer[edi], 0
            JNE vigDecNext
            XOR edi, edi

        vigDecNext:
            INC esi
            LOOP vigDecLoop

        RET

    decrypt_VigenereCipher ENDP


    ; RC4 KSA (Key-Scheduling Algorithm)
    rc4KSA PROC
        PUSHad
        XOR ecx, ecx

        initSBoxLoop:
            MOV rc4State[ecx], cl
            INC ecx
            CMP ecx, 256
            JL  initSBoxLoop

            XOR ecx, ecx            
            XOR ebx, ebx            
            XOR edx, edx            
            
        ksaLoop:
            MOV al, rc4State[ecx]   
            
            PUSH ecx
            MOV esi, OFFSET keyBuffer
            ADD esi, edx            
            MOV ah, [esi]           
            CMP ah, 0               
            JNE keyValid
            
            XOR edx, edx
            MOV esi, OFFSET keyBuffer
            MOV ah, [esi]
        keyValid:
            POP ecx

            ADD bl, al              
            ADD bl, ah              

            MOV al, rc4State[ecx]   
            
            PUSH ecx
            MOVzx ecx, bl           
            MOV ah, rc4State[ecx]   
            POP ecx                 

            MOV rc4State[ecx], ah   
            
            PUSH ecx
            MOVzx ecx, bl
            MOV rc4State[ecx], al   
            POP ecx

            INC edx                 
            INC ecx                 
            CMP ecx, 256
            JL  ksaLoop

        POPad
        RET

    rc4KSA ENDP


    ; RC4 PRGA & Stream Transformation
    rc4Transform PROC
        PUSHad

        CALL rc4KSA

        XOR ecx, ecx            
        XOR esi, esi            
        MOV bl, 0               
        MOV bh, 0               

        prgaLoop:
            CMP ecx, bytesRead      
            JGE prgaDone

            INC bl                  
            
            PUSH ecx
            MOVzx ecx, bl
            MOV al, rc4State[ecx]   
            POP ecx
            
            ADD bh, al              

            PUSH ecx
            MOVzx ecx, bl
            MOV al, rc4State[ecx]   
            
            PUSH ebx
            MOVzx ecx, bh           
            MOV ah, rc4State[ecx]   
            POP ebx

            MOV rc4State[ecx], al   
            
            PUSH ebx
            MOVzx ecx, bl           
            MOV rc4State[ecx], ah   
            POP ebx
            
            POP ecx

            PUSH ecx
            MOVzx ecx, bl
            MOV al, rc4State[ecx]   
            MOVzx ecx, bh
            MOV ah, rc4State[ecx]   
            POP ecx

            ADD al, ah              
            MOVzx edx, al           
            MOV al, rc4State[edx]   

            MOV esi, OFFSET dataBuffer
            ADD esi, ecx            
            XOR [esi], al           

            INC ecx                 
            JMP prgaLoop

        prgaDone:
            POPad
            RET

    rc4Transform ENDP


    ; medium
    encrypt_RC4Cipher PROC

        CALL rc4Transform
        
        RET

    encrypt_RC4Cipher ENDP


    decrypt_RC4Cipher PROC

        CALL rc4Transform

        RET

    decrypt_RC4Cipher ENDP


    ; medium - hard
    encrypt_ChaCha20Cipher PROC

        ; idhar likho

        RET

    encrypt_ChaCha20Cipher ENDP


    decrypt_ChaCha20Cipher PROC

        ; idhar likho

        RET

    decrypt_ChaCha20Cipher ENDP


    ; shows a message in the status line of the dialog
    setStatus PROC hDlg:DWORD, msgPtr:DWORD

        INVOKE SetDlgItemTextA, hDlg, IDC_STATUS, msgPtr

        RET

    setStatus ENDP


    ; shows an error in the status line & in a message box
    showError PROC hDlg:DWORD, msgPtr:DWORD

        INVOKE setStatus, hDlg, msgPtr
        INVOKE MessageBoxA, hDlg, msgPtr, OFFSET captionError, MB_ICONERROR

        RET

    showError ENDP


    ; enables (state = 1) or disables (state = 0) one control of the dialog
    setControlEnabled PROC hDlg:DWORD, ctlId:DWORD, state:DWORD

        INVOKE GetDlgItem, hDlg, ctlId
        INVOKE EnableWindow, eax, state

        RET

    setControlEnabled ENDP


    ; enables the controls needed by the selected input mode (text / file) & disables the rest
    updateInputMode PROC hDlg:DWORD

        INVOKE IsDlgButtonChecked, hDlg, IDC_FILE
        MOV  esi, eax                           ; 1 in file mode
        MOV  edi, 1
        SUB  edi, esi                           ; 1 in text mode

        INVOKE setControlEnabled, hDlg, IDC_INPATH,    esi
        INVOKE setControlEnabled, hDlg, IDC_BROWSEIN,  esi
        INVOKE setControlEnabled, hDlg, IDC_OUTPATH,   esi
        INVOKE setControlEnabled, hDlg, IDC_BROWSEOUT, esi
        INVOKE setControlEnabled, hDlg, IDC_TEXTIN,    edi
        INVOKE setControlEnabled, hDlg, IDC_HEX,       edi

        RET

    updateInputMode ENDP


    ; lets the user pick a file with the open (isSave = 0) or save (isSave = 1) dialog & puts the path in the edit box
    browseFile PROC hDlg:DWORD, ctlId:DWORD, pathPtr:DWORD, isSave:DWORD

        ; keeps whatever is already typed in the box as the starting file name
        INVOKE GetDlgItemTextA, hDlg, ctlId, pathPtr, MEDIUM_SIZE

        MOV  ofn.lStructSize, SIZEOF OPENFILENAME
        MOV  eax, hDlg
        MOV  ofn.hwndOwner, eax
        MOV  ofn.lpstrFilter, OFFSET filterAll
        MOV  ofn.nFilterIndex, 1
        MOV  eax, pathPtr
        MOV  ofn.lpstrFile, eax
        MOV  ofn.nMaxFile, MEDIUM_SIZE

        CMP  isSave, 1
        JE   browseSave

        browseOpen:
            MOV  ofn.Flags, OFN_FILEMUSTEXIST OR OFN_PATHMUSTEXIST OR OFN_HIDEREADONLY
            INVOKE GetOpenFileNameA, OFFSET ofn
            JMP  browseDone

        browseSave:
            MOV  ofn.Flags, OFN_OVERWRITEPROMPT OR OFN_PATHMUSTEXIST OR OFN_HIDEREADONLY
            INVOKE GetSaveFileNameA, OFFSET ofn

        browseDone:
            CMP  eax, 0                         ; 0 means the user cancelled
            JE   browseCancel
            INVOKE SetDlgItemTextA, hDlg, ctlId, pathPtr

        browseCancel:
            RET

    browseFile ENDP


    ; converts the bytesRead bytes of dataBuffer into upper case hex text inside hexBuffer
    bytesToHex PROC

        MOV esi, OFFSET dataBuffer
        MOV edi, OFFSET hexBuffer
        MOV ecx, bytesRead

        hexEncodeLoop:
            MOVZX eax, BYTE PTR [esi]
            MOV   edx, eax
            SHR   eax, 4                        ; high nibble
            AND   edx, 0Fh                      ; low nibble
            MOV   al, hexDigits[eax]
            MOV   [edi], al
            MOV   dl, hexDigits[edx]
            MOV   [edi + 1], dl
            ADD   edi, 2
            INC   esi
            LOOP  hexEncodeLoop

        MOV BYTE PTR [edi], 0                   ; null terminator

        RET

    bytesToHex ENDP


    ; converts the hex text in hexBuffer into bytes inside dataBuffer & sets bytesRead, carry flag is set if the text is not valid hex
    hexToBytes PROC

        MOV esi, OFFSET hexBuffer
        MOV edi, OFFSET dataBuffer
        XOR ecx, ecx                            ; counts the hex digits seen so far

        hexDecodeLoop:
            MOV al, [esi]
            INC esi
            CMP al, 0
            JE  hexDecodeEnd
            CMP al, ' '
            JBE hexDecodeLoop                   ; skips spaces, tabs & line breaks

            CMP al, '0'
            JB  hexInvalid
            CMP al, '9'
            JBE hexIsNumber

            AND al, 0DFh                        ; lower case letters -> upper case
            CMP al, 'A'
            JB  hexInvalid
            CMP al, 'F'
            JA  hexInvalid
            SUB al, 'A' - 10
            JMP hexHaveValue

        hexIsNumber:
            SUB al, '0'

        hexHaveValue:
            TEST ecx, 1
            JNZ  hexLowNibble

            SHL al, 4                           ; first digit of a pair is the high nibble
            MOV dl, al
            JMP hexNextDigit

        hexLowNibble:
            OR  al, dl                          ; second digit completes the byte
            MOV [edi], al
            INC edi

        hexNextDigit:
            INC ecx
            JMP hexDecodeLoop

        hexDecodeEnd:
            TEST ecx, 1                         ; an odd number of digits can not form whole bytes
            JNZ  hexInvalid

            MOV eax, edi
            SUB eax, OFFSET dataBuffer
            MOV bytesRead, eax
            CLC
            RET

        hexInvalid:
            STC
            RET

    hexToBytes ENDP


    ; reads the text box, runs the active cipher & shows the result in the result box
    runTextMode PROC hDlg:DWORD

        INVOKE IsDlgButtonChecked, hDlg, IDC_HEX
        MOV  isHexText, al

        ; hex text is only read as hex while decrypting (encryption always reads the text as it is)
            CMP  isModeEncryption, 1
            JE   readRawText
            CMP  isHexText, 1
            JNE  readRawText

        readHexText:
            INVOKE GetDlgItemTextA, hDlg, IDC_TEXTIN, OFFSET hexBuffer, HEX_SIZE
            CALL hexToBytes
            JC   textHexError
            JMP  validateText

        readRawText:
            INVOKE GetDlgItemTextA, hDlg, IDC_TEXTIN, OFFSET dataBuffer, LARGE_SIZE
            MOV  bytesRead, eax

        validateText:
            ; Validate empty text input
            CMP  bytesRead, 0
            JE   textEmptyError

            ; run active cipher in place
            CALL dispatchCipher

            MOV  edi, bytesRead
            MOV  dataBuffer[edi], 0             ; null terminates the result so that it can be displayed

            ; the result is shown as hex only while encrypting
            CMP  isModeEncryption, 1
            JNE  showRawText
            CMP  isHexText, 1
            JNE  showRawText

            CALL bytesToHex
            INVOKE SetDlgItemTextA, hDlg, IDC_TEXTOUT, OFFSET hexBuffer
            JMP  textDone

        showRawText:
            INVOKE SetDlgItemTextA, hDlg, IDC_TEXTOUT, OFFSET dataBuffer

        textDone:
            INVOKE setStatus, hDlg, OFFSET successMsg
            RET

        textHexError:
            INVOKE showError, hDlg, OFFSET errHexMsg
            RET

        textEmptyError:
            INVOKE showError, hDlg, OFFSET emptyInputMsg
            RET

    runTextMode ENDP


    ; reads the source file chunk by chunk, runs the active cipher on every chunk & writes it to the output file
    runFileMode PROC hDlg:DWORD

        INVOKE GetDlgItemTextA, hDlg, IDC_INPATH, OFFSET inputFilePath, MEDIUM_SIZE
        CMP  eax, 0
        JE   fileEmptyError
        INVOKE GetDlgItemTextA, hDlg, IDC_OUTPATH, OFFSET outputFilePath, MEDIUM_SIZE
        CMP  eax, 0
        JE   fileEmptyError

        ; open inputFile
            INVOKE CreateFileA, OFFSET inputFilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
            MOV  inputHandle, eax
            CMP  eax, INVALID_HANDLE_VALUE
            JE   fileOpenError

        ; create outputFile
            INVOKE CreateFileA, OFFSET outputFilePath, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
            MOV  outputHandle, eax
            CMP  eax, INVALID_HANDLE_VALUE
            JE   closeInputFile

        fileLoop:
            ; reading data chunk from input file into dataBuffer
            INVOKE ReadFile, inputHandle, OFFSET dataBuffer, LARGE_SIZE, OFFSET bytesRead, 0
            CMP  eax, 0
            JE   fileIOError
            CMP  bytesRead, 0
            JE   fileSuccess                    ; EOF reached

            ; run active cipher on chunk
            CALL dispatchCipher

            ; Write transformed chunk
                INVOKE WriteFile, outputHandle, OFFSET dataBuffer, bytesRead, OFFSET bytesWritten, 0
                CMP  eax, 0
                JE   fileIOError

            JMP  fileLoop

        fileSuccess:
            INVOKE setStatus, hDlg, OFFSET successMsg
            JMP  fileClose

        fileIOError:
            INVOKE showError, hDlg, OFFSET errIOMsg

        fileClose:
            INVOKE CloseHandle, inputHandle
            INVOKE CloseHandle, outputHandle
            RET

        closeInputFile:
            ; closes the already opened inputFile so it doesnt stay locked
            INVOKE CloseHandle, inputHandle

        fileOpenError:
            INVOKE showError, hDlg, OFFSET errOpenMsg
            RET

        fileEmptyError:
            INVOKE showError, hDlg, OFFSET emptyInputMsg
            RET

    runFileMode ENDP


    ; collects the settings of the dialog & hands over to the text or file engine
    runEngine PROC hDlg:DWORD

        INVOKE setStatus, hDlg, OFFSET emptyStatus

        ; reading the cipherKey
        INVOKE GetDlgItemTextA, hDlg, IDC_KEY, OFFSET keyBuffer, SMALL_SIZE
        CMP  eax, 0
        JE   engineEmptyError

        ; chosen cipher & mode
        INVOKE SendDlgItemMessageA, hDlg, IDC_CIPHER, CB_GETCURSEL, 0, 0
        MOV  activeCipherIndex, eax             ; Save chosen cipher index globally
        INVOKE IsDlgButtonChecked, hDlg, IDC_ENCRYPT
        MOV  isModeEncryption, al

        ; check input mode (text / file)
        INVOKE IsDlgButtonChecked, hDlg, IDC_FILE
        CMP  eax, 1
        JE   engineFileMode

        engineTextMode:
            INVOKE runTextMode, hDlg
            RET

        engineFileMode:
            INVOKE runFileMode, hDlg
            RET

        engineEmptyError:
            INVOKE showError, hDlg, OFFSET emptyInputMsg
            RET

    runEngine ENDP


    ; the message handler of the main dialog
    dlgProc PROC USES ebx esi edi, hDlg:DWORD, uMsg:DWORD, wParam:DWORD, lParam:DWORD

        CMP  uMsg, WM_INITDIALOG
        JE   onInitDialog
        CMP  uMsg, WM_COMMAND
        JE   onCommand
        CMP  uMsg, WM_CLOSE
        JE   onClose

        XOR  eax, eax                           ; FALSE: message not handled
        RET

        onInitDialog:
            ; filling the cipher list & selecting the first one
            INVOKE SendDlgItemMessageA, hDlg, IDC_CIPHER, CB_ADDSTRING, 0, OFFSET cipherName1
            INVOKE SendDlgItemMessageA, hDlg, IDC_CIPHER, CB_ADDSTRING, 0, OFFSET cipherName2
            INVOKE SendDlgItemMessageA, hDlg, IDC_CIPHER, CB_ADDSTRING, 0, OFFSET cipherName3
            INVOKE SendDlgItemMessageA, hDlg, IDC_CIPHER, CB_ADDSTRING, 0, OFFSET cipherName4
            INVOKE SendDlgItemMessageA, hDlg, IDC_CIPHER, CB_ADDSTRING, 0, OFFSET cipherName5
            INVOKE SendDlgItemMessageA, hDlg, IDC_CIPHER, CB_SETCURSEL, 0, 0

            ; initial selections: encryption, text input, hex text
            INVOKE CheckRadioButton, hDlg, IDC_ENCRYPT, IDC_DECRYPT, IDC_ENCRYPT
            INVOKE CheckRadioButton, hDlg, IDC_TEXT, IDC_FILE, IDC_TEXT
            INVOKE CheckDlgButton, hDlg, IDC_HEX, 1

            INVOKE updateInputMode, hDlg

            MOV  eax, 1                         ; TRUE: lets windows set the default focus
            RET

        onCommand:
            MOV  eax, wParam
            AND  eax, 0FFFFh                    ; low word of wParam is the id of the control

            CMP  eax, IDC_RUN
            JE   doRun
            CMP  eax, IDC_BROWSEIN
            JE   doBrowseInput
            CMP  eax, IDC_BROWSEOUT
            JE   doBrowseOutput
            CMP  eax, IDC_TEXT
            JE   doUpdateMode
            CMP  eax, IDC_FILE
            JE   doUpdateMode
            CMP  eax, IDCANCEL
            JE   onClose

            XOR  eax, eax
            RET

        doRun:
            INVOKE runEngine, hDlg
            MOV  eax, 1
            RET

        doBrowseInput:
            INVOKE browseFile, hDlg, IDC_INPATH, OFFSET inputFilePath, 0
            MOV  eax, 1
            RET

        doBrowseOutput:
            INVOKE browseFile, hDlg, IDC_OUTPATH, OFFSET outputFilePath, 1
            MOV  eax, 1
            RET

        doUpdateMode:
            INVOKE updateInputMode, hDlg
            MOV  eax, 1
            RET

        onClose:
            INVOKE EndDialog, hDlg, 0
            MOV  eax, 1
            RET

    dlgProc ENDP



    main PROC

        INVOKE GetModuleHandleA, 0
        INVOKE DialogBoxParamA, eax, IDD_MAIN, 0, OFFSET dlgProc, 0
        INVOKE ExitProcess, 0

    main ENDP


END main
