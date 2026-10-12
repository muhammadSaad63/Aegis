INCLUDE Irvine32.inc

; constants
SMALL_SIZE  = 64
MEDIUM_SIZE = 256
LARGE_SIZE  = 4096

; variables
.data
    ; data buffers
    bytesRead      DWORD ?
    inputHandle    DWORD ?
    outputHandle   DWORD ?

    ; string buffers
    keyBuffer      BYTE SMALL_SIZE  DUP(?)
    dataBuffer     BYTE LARGE_SIZE  DUP(?)
	inputFilePath  BYTE MEDIUM_SIZE DUP(?)
    outputFilePath BYTE MEDIUM_SIZE DUP(?)

    ; prompt strings
    promptIn       BYTE "Enter source file path:                ", 0
    promptOut      BYTE "Enter output file path:                ", 0
    promptKey      BYTE "Enter encryption key/passphrase:       ", 0
    errOpenMsg     BYTE "Error: Failed to open or create file.  ", 0

.code
    ; collects file paths and passphrase from the user
    promptUser PROC
        ; prompting for inputFilePath
        MOV  edx, OFFSET promptIn
        CALL WriteString
        MOV  edx, OFFSET inputFilePath
        MOV  ecx, MEDIUM_SIZE
        CALL ReadString

        ; prompting for outputFilePath
        MOV  edx, OFFSET promptOut
        CALL WriteString
        MOV  edx, OFFSET outputFilePath
        MOV  ecx, MEDIUM_SIZE
        CALL ReadString

        ; prompting for the cipherKey
        MOV  edx, OFFSET promptKey
        CALL WriteString
        MOV  edx, OFFSET keyBuffer
        MOV  ecx, SMALL_SIZE
        CALL ReadString

        ret
    promptUser ENDP

    ; opens the inputFile & outputFile
    openFiles PROC

        ; open inputFile
        oprnsInputFile:
            MOV  edx, OFFSET inputFilePath
            CALL OpenInputFile
            MOV  inputHandle, eax
            CMP  eax, INVALID_HANDLE_VALUE
            JE   handleError

        ; create outputFile
        createsOutputFile:
            MOV  edx, OFFSET outputFilePath
            CALL CreateOutputFile
            MOV  outputHandle, eax
            CMP  eax, INVALID_HANDLE_VALUE
            JE   handleError

        JMP openSuccess

        handleError:
            MOV  edx, OFFSET errOpenMsg
            CALL WriteString
            CALL Crlf

        openSuccess:
            RET

    openFiles ENDP


    ProcessStream PROC

        ; reads up to 4,096 bytes from inputHandle and put them into dataBuffer
        readDataFromFile:
                MOV  eax, inputHandle
                MOV  edx, OFFSET dataBuffer
                MOV  ecx, LARGE_SIZE                      ; LARGE_SIZE = 4096 bytes
                CALL ReadFromFile
                JC   handleError

        checkEOF:
            MOV bytesRead, eax                                ; eax holds the exact number of bytes read
            CMP eax, 0                                        ; checks if we hit the End Of File
            JE  closeFiles

        ; run xor transformation on the loaded chunk
        CALL XORCipher

        ; writes transformed chunk to output file
        writeDataToFile:
            MOV  eax, outputHandle
            MOV  edx, OFFSET dataBuffer
            MOV  ecx, bytesRead
            CALL WriteToFile
            JC   handleError

            JMP  readDataFromFile

        closeFiles:
            MOV  eax, inputHandle
            CALL CloseFile
            MOV  eax, outputHandle
            CALL CloseFile

        processSuccess:
            MOV  edx, OFFSET successMsg
            CALL WriteString
            CALL Crlf

        handleError:
            RET

    ProcessStream ENDP

    ; very easy
    XORCipher PROC
        MOV esi, OFFSET dataBuffer      ; holds address of data chunk
        MOV ecx, bytesRead              ; loop counter
        XOR edi, edi                    ; effectively MOV edi, 0

        getCipherKey:
            MOV al, keyBuffer[edi]      ; get current key byte
            CMP al, 0                   ; checks for null terminator of key string
            JNE applyXOR                ; if al != 0 (ie the null terminator), jumnp to applyXOR
            XOR edi, edi                ; reset key index (wrap around) if null terminator reached
            MOV al, keyBuffer[edi]      ; get value at start of key

        applyXOR:
            XOR [esi], al               ; apply bitwise xor to a byte of the data chunk
            INC esi                     ; move to next data byte
            INC edi                     ; move to next key byte
            
            LOOP getCipherKey           ; decrements ecx and then gets the next key if ecx != 0

        ret
    XORCipher ENDP

    ; very easy
    CaesarCipher PROC

        ret
    CaesarCipher ENDP

    ; easy
    RailFenceCipher PROC

        ret
    RailFenceCipher ENDP

    ; easy - medium
    VigenereCipher PROC

        ret
    VigenereCipher ENDP

    ; medium
    RC4Cipher PROC

        ret
    RC4Cipher ENDP

    ; medium - hard
    ChaCha20Cipher PROC

        ret
    ChaCha20Cipher ENDP

    ; hard
    DESCipher PROC

        ret
    DESCipher ENDP

    ; very hard
    AES128Cipher PROC

        ret
    AES128Cipher ENDP

	main PROC
        CALL promptUser
        CALL openFiles

		exit
	main ENDP


END main