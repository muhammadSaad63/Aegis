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