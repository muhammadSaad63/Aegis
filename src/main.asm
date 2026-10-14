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

    ; arr of procedure pointers
    encryptionCiphers DWORD OFFSET encrypt_XORCipher,
                        OFFSET encrypt_CaesarCipher,
                        OFFSET encrypt_RailFenceCipher,
                        OFFSET encrypt_VigenereCipher,
                        OFFSET encrypt_RC4Cipher,
                        OFFSET encrypt_ChaCha20Cipher

    decryptionCiphers DWORD OFFSET decrypt_XORCipher,
                        OFFSET decrypt_CaesarCipher,
                        OFFSET decrypt_RailFenceCipher,
                        OFFSET decrypt_VigenereCipher,
                        OFFSET decrypt_RC4Cipher,
                        OFFSET decrypt_ChaCha20Cipher

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
    bannerLine10 BYTE "  [M] Toggle Mode:   [ ENCRYPTION ]                ", 0Ah, 0Dh, 0
    bannerLine11 BYTE "  [I] Toggle Input:  [ FILE ]                      ", 0Ah, 0Dh, 0
    bannerLine12 BYTE "---------------------------------------------------", 0Ah, 0Dh, 0
    bannerLine13 BYTE "  [X] Exit Aegis                                   ", 0Ah, 0Dh, 0 
    bannerLine14 BYTE "                                                   ", 0Ah, 0Dh, 0 
    bannerLine15 BYTE "===================================================", 0Ah, 0Dh, 0
    bannerLine16 BYTE "                                                   ", 0Ah, 0Dh, 0
    bannerLine17 BYTE "Select an option (1 - 5 / M / I / X): ", 0

    invalidInputMsg BYTE "[!] Invalid Input: Input can only be among {1 - 5, M, I, X}.", 0

    ; control flags
    isInputFile       BYTE  0               ; 0: text, 1: file              | initially set for text input
    isModeEncryption  BYTE  1               ; 0: decryption, 1: encryption  | initially set for encryption
    activeCipherIndex DWORD 0

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
            STC                    ; set carry flag to indicate error
            RET

        openSuccess:
            CLC                    ; clear carry flag on success
            RET

    openFiles ENDP


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


    ; responsible for managing and carrying the ciphers-stuff
    executeEngine PROC

        MOV activeCipherIndex, eax   ; Save chosen cipher index globally

        ; check input mode: isInputFile (0: Text, 1: File)
            CMP isInputFile, 1
            JE  runFileMode

        runTextMode:
            ; printing prompt
            MOV  edx, OFFSET promptKey
            CALL WriteString

            ; reading plaintext
            MOV  edx, OFFSET dataBuffer
            MOV  ecx, LARGE_SIZE
            CALL ReadString                          ; grabs text string from user
            MOV  bytesRead, eax                      ; saves string length

            ; run active cipher in place
            CALL dispatchCipher

            ; print ciphertext
            MOV edx, OFFSET dataBuffer
            CALL WriteString
            CALL Crlf

            RET

        runFileMode:
            CALL promptUser              ; get source and destination paths + key
            CALL openFiles               ; opens handles
            JC   engineClose             ; aborts if file open failed

            fileLoop:
                ; reading data chunk from input file into dataBuffer
                CALL ReadFromFile
                JC   closeFiles
                MOV  bytesRead, eax
                CMP  eax, 0
                JE   engineSuccess       ; EOF reached

                ; run active cipher on chunk
                CALL dispatchCipher

                ; Write transformed chunk
                    MOV  eax, outputHandle
                    MOV  edx, OFFSET dataBuffer
                    MOV  ecx, bytesRead
                    CALL WriteToFile
                    JC   closeFiles

                JMP  fileLoop

        engineSuccess:
            MOV edx, OFFSET successMsg
            CALL WriteString
            CALL Crlf

        closeFiles:
            MOV  eax, inputHandle
            CALL CloseFile
            MOV  eax, outputHandle
            CALL CloseFile

        engineClose:
            RET

    executeEngine ENDP


    ; continously reads & writes data from the files & performs algorithms on em
    ProcessStream PROC

        ; reads up to 4,096 bytes from inputHandle and put them into dataBuffer
        readDataFromFile:
            MOV  eax, inputHandle
            MOV  edx, OFFSET dataBuffer
            MOV  ecx, LARGE_SIZE                       ; LARGE_SIZE = 4096 bytes
            CALL ReadFromFile
            JC   handleError

        checkEOF:
            MOV bytesRead, eax                            ; eax holds the exact number of bytes read
            CMP eax, 0                                    ; checks if we hit the End Of File
            JE  closeFiles

        ; run xor transformation on the loaded chunk
        ;CALL XORCipher

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


    decrypt_XORCipher PROC
        RET
    decrypt_XORCipher ENDP


    ; very easy
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
            INC esi                                                   ; move to next byte of dataBuffer
            LOOP applyCipher

        RET

    encrypt_CaesarCipher ENDP


    decrypt_CaesarCipher PROC
        RET
    decrypt_CaesarCipher ENDP


    ; easy
    encrypt_RailFenceCipher PROC

        ret
    encrypt_RailFenceCipher ENDP


    decrypt_RailFenceCipher PROC
        ret
    decrypt_RailFenceCipher ENDP


    ; easy - medium
    encrypt_VigenereCipher PROC

        ret
    encrypt_VigenereCipher ENDP


    decrypt_VigenereCipher PROC
        ret
    decrypt_VigenereCipher ENDP


    ; medium
    encrypt_RC4Cipher PROC

        ret
    encrypt_RC4Cipher ENDP


    decrypt_RC4Cipher PROC
        ret
    decrypt_RC4Cipher ENDP


    ; medium - hard
    encrypt_ChaCha20Cipher PROC

        ret
    encrypt_ChaCha20Cipher ENDP


    decrypt_ChaCha20Cipher PROC
        ret
    decrypt_ChaCha20Cipher ENDP


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
                CMP al, '1'             ; < 1
                JB  invalidInput         
                CMP al, '5'             ; >= 1 & <= 5
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
            DEC   al
            MOVZX eax, al

            CALL  executeEngine
            RET

        doToggleMode:
            MOV al, isModeEncryption
            XOR al, 1                       ; toggling the value of the status flag
            MOV isModeEncryption, al
            
            CALL toggleModeString
            RET

        doToggleInput:
            MOV al, isInputFile
            XOR al, 1                       ; toggling the value of the status flag
            MOV isInputFile, al

            CALL toggleInputString
            RET

        doExit:
            EXIT                     ; Or jump to your exit program label

    processInput ENDP


    ; updates the text of bannerLine10 upon entering of M (DE <-> EN)    
    toggleModeString PROC

            MOV esi, OFFSET bannerLine10 + 22   

            CMP BYTE PTR [esi], 'E'        ; if text in banner is currently encryption
            JE  updateToDecryption

        updateToEncryption:
            MOV BYTE PTR [esi],     'E'
            MOV BYTE PTR [esi + 1], 'N'

            RET

        updateToDecryption:
            MOV BYTE PTR [esi],     'D'
            MOV BYTE PTR [esi + 1], 'E'    

            RET

    toggleModeString ENDP


    ; updates the text of bannerLine11 upon entering of I (FILE <-> TEXT)
    toggleInputString PROC
        
        MOV esi, OFFSET (bannerLine11 + 22)          ; 22 being the relative position of start of encryption/decryption word in bannerLine10

        CMP BYTE PTR [esi], 'F'                            ; if text is currently FILE
        JE  updateToText

        updateToFile:
            MOV BYTE PTR [esi],      'F'
            MOV BYTE PTR [esi + 1], 'I'
            MOV BYTE PTR [esi + 2], 'L'
            MOV BYTE PTR [esi + 3], 'E'
            
            RET

        updateToText:
            MOV BYTE PTR [esi],      'T'
            MOV BYTE PTR [esi + 1], 'E'
            MOV BYTE PTR [esi + 2], 'X'
            MOV BYTE PTR [esi + 3], 'T'   
        
            RET

    toggleInputString ENDP



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
            CALL processInput

            JMP  program

        endProg:
            RET

    main ENDP


END main