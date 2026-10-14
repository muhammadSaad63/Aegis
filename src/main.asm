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
    successMsg     BYTE "Success!", 0

    ; Rail Fence Cipher variables
    railBuffer     BYTE   LARGE_SIZE DUP(?)
    railCount      DWORD  ?
    targetRail     DWORD  ?
    currentRail    DWORD  ?
    railDirection  SDWORD ?
    scanIndex      DWORD  ?
    outputIndex    DWORD  ?

    ; Array of procedure pointers (each OFFSET is 4 bytes)
    cipherJumpTable DWORD   OFFSET XORCipher,
                            OFFSET CaesarCipher,
                            OFFSET RailFenceCipher,
                            OFFSET VigenereCipher,
                            OFFSET RC4Cipher,
                            OFFSET ChaCha20Cipher

    ; using indivdual lines instead of a single, long string due to max line length limit in masm issue
    bannerLine1  BYTE "===================================================", 0Ah, 0Dh, 0
    bannerLine2  BYTE "                   [  A E G I S  ]                 ", 0Ah, 0Dh, 0
    bannerLine3  BYTE "         Modular Cryptographic Engine v1.0         ", 0Ah, 0Dh, 0
    bannerLine4  BYTE "===================================================", 0Ah, 0Dh, 0
    bannerLine5  BYTE "                                                   ", 0Ah, 0Dh, 0
    bannerLine6  BYTE "  [1] XOR Cipher            [4] Vigenere Cipher    ", 0Ah, 0Dh, 0
    bannerLine7  BYTE "  [2] Caesar Cipher         [5] RC4/ChaCha20 ARX   ", 0Ah, 0Dh, 0
    bannerLine8  BYTE "  [3] Rail Fence                                   ", 0Ah, 0Dh, 0
    bannerLine9  BYTE "---------------------------------------------------", 0Ah, 0Dh, 0
    bannerLine10 BYTE "  [M] Toggle Mode:  [ ENCRYPTION ]                 ", 0Ah, 0Dh, 0
    bannerLine11 BYTE "  [I] Toggle Input: [ FILE ]                       ", 0Ah, 0Dh, 0
    bannerLine12 BYTE "---------------------------------------------------", 0Ah, 0Dh, 0
    bannerLine13 BYTE "  [X] Exit Aegis                                   ", 0Ah, 0Dh, 0 
    bannerLine14 BYTE "                                                   ", 0Ah, 0Dh, 0 
    bannerLine15 BYTE "===================================================", 0Ah, 0Dh, 0
    bannerLine16 BYTE "                                                   ", 0Ah, 0Dh, 0
    bannerLine17 BYTE "Select an option (1 - 5 / M / I / X): ", 0

    invalidInputMsg BYTE "[!] Invalid Input: Input can only be among {1 - 5, M, I, X}.", 0

.code

    ; collects file paths and passphrase from the user
    promptUser PROC
        ; prompting for inputFilePath
        promptForInputFilePath:
            MOV  edx, OFFSET promptIn
            CALL WriteString
            MOV  edx, OFFSET inputFilePath
            MOV  ecx, MEDIUM_SIZE
            CALL ReadString

        ; prompting for outputFilePath
        promptForOutputFilePath:
            MOV  edx, OFFSET promptOut
            CALL WriteString
            MOV  edx, OFFSET outputFilePath
            MOV  ecx, MEDIUM_SIZE
            CALL ReadString

        ; prompting for the cipherKey
        promptForCipherKey:
            MOV  edx, OFFSET promptKey
            CALL WriteString
            MOV  edx, OFFSET keyBuffer
            MOV  ecx, SMALL_SIZE
            CALL ReadString

        RET
        
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
            STC                  ; set carry flag to indicate error
            RET

        openSuccess:
            CLC                  ; clear carry flag on success
            RET

    openFiles ENDP


    ; dynamically chooses the enc/dec algo to use based upon userChoice
    callAlgorithm PROC

        ; Bounds check to make sure it's valid (0 to 5)
        validateChoice:
            CMP eax, LENGTHOF cipherJumpTable
            JBE callCipher

        invalidChoice:
            MOV  edx, OFFSET invalidChoice
            CALL WriteString
            RET

        ; Call the procedure dynamically using the table offset!
        callCipher:
            DEC eax                     ; Convert 1-based menu choice to 0-based index (0 = XOR, 1 = Caesar, etc.)
            CALL cipherJumpTable[eax * TYPE cipherJumpTable]

        RET

    callAlgorithm ENDP


    ; continously reads & writes data from the files & performs algorithms on em
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


    ; performs the very basic XOR cipher on the data chunk
    XORCipher PROC

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

    XORCipher ENDP


    ; very easy
    CaesarCipher PROC
        initializeRegs:
                MOV esi, OFFSET dataBuffer                              ; points to source data chunk
                MOV ecx, bytesRead                                      ; the loop counter = bytes actually read
                MOV bl, 3                                               ; using a arbitrary shift of 3 for now

        applyCipher:
            MOV al, [esi]                                               ; Load current byte

            checkUpperCase:
                ; check if byte is uppercase (A-Z -> ascii 65 to 90)
                    CMP al, 'A'
                    JB  skipByte                                        ; skip the byte if its ascii value is below A (ie it aint a alphabet)
                    CMP al, 'Z'
                    JA  checkLowerCase                                  ; if the byte is greater than Z, go check if it is lowercase
                
                ; handle uppercase shift with wrapAround
                    ADD al, bl                                          ; apply shift
                    CMP al, 'Z'                                         
                    JBE storeByte                                       ; stores the byte if it below or eual to Z
                    SUB al, 26                                          ; wrap around if past Z
                    JMP storeByte

            checkLowerCase:
                ; check if byte is lowercased (a-z -> ascii 97 to 122)
                    CMP al, 'a'
                    JB  skipByte                                        ; skips if ascii value of byte is > Z & < a (ie bw Z and a)
                    CMP al, 'z'
                    JA  skipByte                                        ; skips if ascii value of byte is > a (ie > 122)

                ; handle lowerCase shift with wrapAround
                    ADD al, bl                                          ; apply shift
                    CMP al, 'z'
                    JBE storeByte
                    SUB al, 26                                          ; wrap around if past z
                    JMP storeByte  

            storeByte:
                MOV [esi], al                                           ; saves transformed byte back inPlace

        skipByte:
            INC esi                                                     ; move to next byte of dataBuffer
            LOOP applyCipher

        RET

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


    printMenu PROC

        CALL ClrScr

        ; Set text to Bright Cyan (0Bh) for the header banner
        MOV eax, 0Bh                    
        CALL SetTextColor

        MOV EDX, OFFSET bannerLine1
        CALL WriteString
        MOV EDX, OFFSET bannerLine2
        CALL WriteString
        MOV EDX, OFFSET bannerLine3
        CALL WriteString
        MOV EDX, OFFSET bannerLine4
        CALL WriteString
        MOV EDX, OFFSET bannerLine5
        CALL WriteString

        ; Change text to Bright Yellow (0Eh) for the ciphers
        MOV eax, 0Eh                    
        CALL SetTextColor

        MOV EDX, OFFSET bannerLine6
        CALL WriteString
        MOV EDX, OFFSET bannerLine7
        CALL WriteString
        MOV EDX, OFFSET bannerLine8
        CALL WriteString

        ; Change text to Darker Gray/Blue (08h) for the divider lines & toggles
        MOV eax, 08h                    
        CALL SetTextColor

        MOV EDX, OFFSET bannerLine9
        CALL WriteString
        MOV EDX, OFFSET bannerLine10
        CALL WriteString
        MOV EDX, OFFSET bannerLine11
        CALL WriteString
        MOV EDX, OFFSET bannerLine12
        CALL WriteString

        ; Change text to Bright Red (0Ch) for Exit and Prompt section
        MOV eax, 0Ch                    
        CALL SetTextColor

        MOV EDX, OFFSET bannerLine13
        CALL WriteString
        MOV EDX, OFFSET bannerLine14
        CALL WriteString
        MOV EDX, OFFSET bannerLine15
        CALL WriteString
        MOV EDX, OFFSET bannerLine16
        CALL WriteString

        ; Reset back to default white-on-black (07h) before reading user choice
        MOV eax, 07h                    
        CALL SetTextColor

        RET

    printMenu ENDP


    ; continously prompts user for input, reads it, and then validates it until the input acceptable
    getInput PROC

        promptLoop:
            ; printing prompt msg
                CALL Crlf
                MOV EDX, OFFSET bannerLine17
                CALL WriteString

            ; displaying the char which user input
                CALL ReadChar
                CALL WriteChar
                CALL Crlf

            ; check for exit ('X' or 'x')
                CMP al, 'X'
                JE  validInput
                CMP al, 'x'
                JE  validInput

            ; check for mode toggle ('M' or 'm')
                CMP al, 'M'
                JE  validInput
                CMP al, 'm'
                JE  validInput

            ; check for input toggle ('I' or 'i')
                CMP al, 'I'
                JE  validInput
                CMP al, 'i'
                JE  validInput

            ; check for cipher choices ('1' through '5')
                CMP al, '1'              ; < 1
                JB  invalidInput         
                CMP al, '5'              ; >= 1 & <= 5
                JBE validInput              
        
        invalidInput:
            ; set textColor to red
            MOV  eax, 0Ch                    
            CALL SetTextColor
            
            ; print error string
            MOV  edx, OFFSET invalidInputMsg
            CALL WriteString

            ; reset text color to white
            MOV  eax, 07h               
            CALL SetTextColor
            
            CALL Crlf
            JMP promptLoop

        validInput:
            RET

    getInput ENDP


    ; receives the validated character in AL and processes it
    processInput PROC
        ; check exit
            CMP al, 'X'
            JE  doExit
            CMP al, 'x'
            JE  doExit

        ; check toggle mode
            CMP al, 'M'
            JE  doToggleMode
            CMP al, 'm'
            JE  doToggleMode

        ; check toggle input-source
            CMP al, 'I'
            JE  doToggleInput
            CMP al, 'i'
            JE  doToggleInput

        ; if none of above, its a cipher choice (1-5)
            SUB   al, '0'            ; converting ascii to int (1-5)
;            MOVZX eax, al
            CALL  callAlgorithm
            RET

        doToggleMode:
            ; Call your mode-toggling logic here
            RET

        doToggleInput:
            ; Call your input-source-toggling logic here
            RET

        doExit:
            EXIT                   ; Or jump to your exit program label

    processInput ENDP


	main PROC
        ; CALL promptUser
        ; CALL openFiles
        ; JC   exitProgram        ; exit if opening files failed (checks if carry flag is set)

        ; CALL ProcessStream

        ; exitProgram:
        ;     exit

        program:
            CALL printMenu
            CALL getInput

            ;CALL processInput
            JC   endProg
            JMP  program

        endProg:
            RET

	main ENDP


END main