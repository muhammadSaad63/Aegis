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
        MOV  edx, OFFSET inputFilePath
        CALL OpenInputFile
        MOV  inputHandle, eax
        CMP  eax, INVALID_HANDLE_VALUE
        JE   handleError

        ; create outputFile
        MOV  edx, OFFSET outputFilePath
        CALL CreateOutputFile
        MOV  outputHandle, eax
        CMP  eax, INVALID_HANDLE_VALUE
        JE   handleError

        handleError:
            mov edx, OFFSET errOpenMsg
            call WriteString
            call Crlf

        ret
    openFiles ENDP

	main PROC
        CALL promptUser
        CALL openFiles

		exit
	main ENDP


END main