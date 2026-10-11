INCLUDE Irvine32.inc


; constants
SMALL_SIZE  = 64
MEDIUM_SIZE = 256
LARGE_SIZE  = 4096


.data
    ; data holders
    bytesRead      DWORD ?
    inputHandle    DWORD ?
    outputHandle   DWORD ?

    ; string buffers
    keyBuffer      BYTE SMALL_SIZE  DUP(?)
    dataBuffer     BYTE LARGE_SIZE  DUP(?)
	inputFilePath  BYTE MEDIUM_SIZE DUP(?)
    outputFilePath BYTE MEDIUM_SIZE DUP(?)

    ; prompt (msg) strings
    promptIn       BYTE "Enter source file path:          ", 0
    promptOut      BYTE "Enter output file path:          ", 0
    promptKey      BYTE "Enter encryption key/passphrase: ", 0


.code
	main PROC
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

		exit
	main ENDP


END main