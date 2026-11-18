INCLUDE Irvine32.inc

; constants
SMALL_SIZE  = 64
MEDIUM_SIZE = 256
LARGE_SIZE  = 4096
; one ChaCha20 quarter round on four words of chachaWork
chachaQR MACRO a, b, c, d
    MOV eax, chachaWork[a * 4]
    MOV ebx, chachaWork[b * 4]
    MOV ecx, chachaWork[c * 4]
    MOV edx, chachaWork[d * 4]

    ADD eax, ebx
    XOR edx, eax
    ROL edx, 16

    ADD ecx, edx
    XOR ebx, ecx
    ROL ebx, 12

    ADD eax, ebx
    XOR edx, eax
    ROL edx, 8

    ADD ecx, edx
    XOR ebx, ecx
    ROL ebx, 7

    MOV chachaWork[a * 4], eax
    MOV chachaWork[b * 4], ebx
    MOV chachaWork[c * 4], ecx
    MOV chachaWork[d * 4], edx
ENDM
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
    promptIn        BYTE "Enter source file path:                                      ", 0
    promptOut       BYTE "Enter output file path:                                      ", 0
    promptKey       BYTE "Enter encryption key/passphrase:                             ", 0
    promptPlain     BYTE "Enter text to process:                                       ", 0
    errOpenMsg      BYTE "Error: Failed to open or create file.                        ", 0
    errIOMsg        BYTE "Error: Failed to read from or write to file.                 ", 0
    successMsg      BYTE "Success!                                                     ", 0
    emptyInputMsg   BYTE "[!] Error: Input path, text or key cannot be empty.          ", 0
    pressEnterMsg   BYTE "Press any key to return to the menu...                       ", 0
    invalidInputMsg BYTE "[!] Invalid Input: Input can only be among {1 - 6, M, I, X}. ", 0

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
    bannerLine7  BYTE "  [2] Caesar Cipher         [5] RC4 ARX            ", 0Ah, 0Dh, 0
    bannerLine8  BYTE "  [3] Rail Fence            [6] ChaCha20           ", 0Ah, 0Dh, 0
    bannerLine9  BYTE "---------------------------------------------------", 0Ah, 0Dh, 0
    bannerLine10 BYTE "  [M] Toggle Mode:   [ ENCRYPTION ]                ", 0Ah, 0Dh, 0
    bannerLine11 BYTE "  [I] Toggle Input:  [ TEXT ]                      ", 0Ah, 0Dh, 0
    bannerLine12 BYTE "---------------------------------------------------", 0Ah, 0Dh, 0
    bannerLine13 BYTE "  [X] Exit Aegis                                   ", 0Ah, 0Dh, 0 
    bannerLine14 BYTE "                                                   ", 0Ah, 0Dh, 0 
    bannerLine15 BYTE "===================================================", 0Ah, 0Dh, 0
    bannerLine16 BYTE "                                                   ", 0Ah, 0Dh, 0
    bannerLine17 BYTE "Select an option (1 - 6 / M / I / X):              ", 0Ah, 0Dh, 0
    hintLine1    BYTE "    Mode  : encrypt or decrypt your data           ", 0Ah, 0Dh, 0
    hintLine2    BYTE "    Input : TEXT = type here, FILE = use files     ", 0Ah, 0Dh, 0
    hintLine3    BYTE "    Then pick a cipher [1-6] to run it.            ", 0Ah, 0Dh, 0


    ; control flags
    isInputFile       BYTE  0               ; 0: text, 1: file              | initially set for text input
    isModeEncryption  BYTE  1               ; 0: decryption, 1: encryption  | initially set for encryption
    activeCipherIndex DWORD 0
    skipTypewriter    BYTE  0               ; 0: use typewriter, 1: skip typewriter on toggle

    ; ChaCha20 state
    chachaConst   DWORD 61707865h, 3320646Eh, 79622D32h, 6B206574h           ; "expand 32-byte k"
    chachaKey     BYTE  32 DUP(?)
    chachaState   DWORD 16 DUP(?)
    chachaWork    DWORD 16 DUP(?)                                            ; working copy / 64-byte keystream block

    tempBuffer       BYTE LARGE_SIZE DUP(?)
    rc4State         BYTE 256 DUP(?)

.code
     
    Include xor_cipher.inc

    Include caesar_cipher.inc
    
    Include railfence_cipher.inc
    
    Include vigenere_cipher.inc
    
    Include rc4_cipher.inc

    Include chacha20_cipher.inc
    
    ; Pause utility to let user review outputs before redrawing menu
    pauseEngine PROC USES eax edx

        CALL Crlf

        MOV  edx, OFFSET pressEnterMsg
        CALL WriteString
        CALL ReadChar

        CALL Crlf

        RET

    pauseEngine ENDP


    ; Typewriter utility to print strings character by character
    printTypewriter PROC USES esi eax edx

        MOV esi, edx

        typewriterLoop:
            MOV  al, [esi]
            CMP  al, 0
            JE   typewriterDone

            CALL WriteChar

            PUSH eax
            MOV  eax, 35
            CALL Delay
            POP  eax

            INC  esi
            JMP  typewriterLoop

        typewriterDone:
            RET

    printTypewriter ENDP


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
            JE   closeInputFile

        JMP openSuccess

        closeInputFile:
            ; closes the already opened inputFile so it doesnt stay locked
            MOV  eax, inputHandle
            CALL CloseFile

        handleError:
            ; Error message in Bright Red (0Ch)
            MOV  eax, 0Ch
            CALL SetTextColor
            MOV  edx, OFFSET errOpenMsg
            CALL WriteString
            CALL Crlf
            MOV  eax, 07h
            CALL SetTextColor
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
            ; prompting for key in text mode
            MOV  edx, OFFSET promptKey
            CALL WriteString
            MOV  edx, OFFSET keyBuffer
            MOV  ecx, SMALL_SIZE
            CALL ReadString

            ; Validate empty key input
            CMP  keyBuffer, 0
            JE   validationError

            ; printing prompt for text
            MOV  edx, OFFSET promptPlain
            CALL WriteString

            ; reading plaintext
            MOV  edx, OFFSET dataBuffer
            MOV  ecx, LARGE_SIZE
            CALL ReadString                          ; grabs text string from user
            MOV  bytesRead, eax                      ; saves string length

            ; Validate empty text input
            CMP  bytesRead, 0
            JE   validationError

            ; run active cipher in place
            CALL dispatchCipher

            ; print ciphertext
            MOV edx, OFFSET dataBuffer
            CALL WriteString
            CALL Crlf

            CALL pauseEngine

            RET

        runFileMode:
            CALL promptUser              ; get source and destination paths + key
            
            ; Validate empty file paths and key
            CMP  inputFilePath, 0
            JE   validationError
            CMP  outputFilePath, 0
            JE   validationError
            CMP  keyBuffer, 0
            JE   validationError

            CALL openFiles               ; opens handles
            JC   openError               ; aborts if file open failed

            fileLoop:
                ; reading data chunk from input file into dataBuffer with explicit register setup
                MOV  eax, inputHandle
                MOV  edx, OFFSET dataBuffer
                MOV  ecx, LARGE_SIZE
                CALL ReadFromFile
                JC   ioError
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
                    JC   ioError

                JMP  fileLoop

        engineSuccess:
            ; Success message in Bright Green (0Ah)
            MOV  eax, 0Ah
            CALL SetTextColor
            MOV  edx, OFFSET successMsg
            CALL WriteString
            CALL Crlf
            MOV  eax, 07h
            CALL SetTextColor

            CALL pauseEngine                ; ie press enter to continue

            JMP  closeFiles

        ioError:
            ; Error message in Bright Red (0Ch)
            MOV  eax, 0Ch
            CALL SetTextColor
            MOV  edx, OFFSET errIOMsg
            CALL WriteString
            CALL Crlf
            MOV  eax, 07h
            CALL SetTextColor

            CALL pauseEngine
            JMP  closeFiles

        openError:
            CALL pauseEngine                ; lets the user read the error printed by openFiles
            RET

        validationError:
            ; Error message in Bright Red (0Ch)
            MOV  eax, 0Ch
            CALL SetTextColor
            MOV  edx, OFFSET emptyInputMsg
            CALL WriteString
            CALL Crlf
            MOV  eax, 07h
            CALL SetTextColor

            CALL pauseEngine
            RET

        closeFiles:
            MOV  eax, inputHandle
            CALL CloseFile
            MOV  eax, outputHandle
            CALL CloseFile

        engineClose:
            RET

    executeEngine ENDP
   
    ; prints the program menu
    printMenu PROC

        CALL ClrScr

        ; Header banner (Bright Cyan - 0Bh)
            MOV  eax, 0Bh                    
            CALL SetTextColor

            MOV  EDX, OFFSET bannerLine1
            CALL WriteString

            CMP  skipTypewriter, 1
            JE   printInstantBanner
            MOV  EDX, OFFSET bannerLine2
            CALL printTypewriter                ; animated printing for A E G I S only
            JMP  continueBanner

        printInstantBanner:
            MOV  EDX, OFFSET bannerLine2
            CALL WriteString
            MOV  skipTypewriter, 0             ; reset flag

        continueBanner:

            MOV  EDX, OFFSET bannerLine3
            CALL WriteString
            MOV  EDX, OFFSET bannerLine4
            CALL WriteString
            MOV  EDX, OFFSET bannerLine5
            CALL WriteString

            MOV  eax, 25          ; Delay for animation effect
            CALL Delay

        ; Ciphers list (Bright Yellow - 0Eh)
            MOV  eax, 0Eh                    
            CALL SetTextColor

            MOV  EDX, OFFSET bannerLine6
            CALL WriteString
            MOV  EDX, OFFSET bannerLine7
            CALL WriteString
            MOV  EDX, OFFSET bannerLine8
            CALL WriteString

            MOV  eax, 25
            CALL Delay

        ; Dividers & toggles (Darker Gray/Blue - 08h)
            MOV  eax, 08h                    
            CALL SetTextColor

            MOV  EDX, OFFSET bannerLine9
            CALL WriteString
            MOV  EDX, OFFSET bannerLine10
            CALL WriteString
            MOV  EDX, OFFSET bannerLine11
            CALL WriteString
            MOV  EDX, OFFSET hintLine1
            CALL WriteString
            MOV  EDX, OFFSET hintLine2
            CALL WriteString
            MOV  EDX, OFFSET hintLine3
            CALL WriteString
            MOV  EDX, OFFSET bannerLine12
            CALL WriteString

            MOV  eax, 25
            CALL Delay

        ; Exit and prompt section (Bright Red - 0Ch)
            MOV  eax, 0Ch                    
            CALL SetTextColor

            MOV  EDX, OFFSET bannerLine13
            CALL WriteString
            MOV  EDX, OFFSET bannerLine14
            CALL WriteString
            MOV  EDX, OFFSET bannerLine15
            CALL WriteString
            MOV  EDX, OFFSET bannerLine16
            CALL WriteString

        ; reset color back to default white-on-black (07h)
            MOV  eax, 07h                    
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

            ; check for cipher choices ('1' through '6')
                CMP al, '1'             ; < 1
                JB  invalidInput         
                CMP al, '6'             ; >= 1 & <= 6
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
            MOV skipTypewriter, 1           ; skip typewriter on toggle redraw
            
            CALL toggleModeString
            RET

        doToggleInput:
            MOV al, isInputFile
            XOR al, 1                       ; toggling the value of the status flag
            MOV isInputFile, al
            MOV skipTypewriter, 1           ; skip typewriter on toggle redraw

            CALL toggleInputString
            RET

        doExit:
            EXIT                     ; Or jump to your exit program label

    processInput ENDP


    ; updates the text of bannerLine10 upon entering of M (DE <-> EN)    
    toggleModeString PROC

        MOV esi, OFFSET bannerLine10 + 23   

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
        
        MOV esi, OFFSET (bannerLine11 + 23)          ; 23 being the relative position of start of input mode word in bannerLine11

        CMP BYTE PTR [esi], 'F'                            ; if text is currently FILE
        JE  updateToText

        updateToFile:
            MOV BYTE PTR [esi],     'F'
            MOV BYTE PTR [esi + 1], 'I'
            MOV BYTE PTR [esi + 2], 'L'
            MOV BYTE PTR [esi + 3], 'E'
            
            RET

        updateToText:
            MOV BYTE PTR [esi],     'T'
            MOV BYTE PTR [esi + 1], 'E'
            MOV BYTE PTR [esi + 2], 'X'
            MOV BYTE PTR [esi + 3], 'T'   
        
            RET

    toggleInputString ENDP



    main PROC

        program:
            CALL printMenu
            CALL getInput
            CALL processInput

            JMP  program

    main ENDP


END main