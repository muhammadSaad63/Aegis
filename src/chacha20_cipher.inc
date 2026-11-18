    ; builds the initial 16-word ChaCha20 state from keyBuffer
    chachaInit PROC USES eax ecx esi edi

        ; words 0-3: the constants
            MOV  esi, OFFSET chachaConst
            MOV  edi, OFFSET chachaState
            MOV  ecx, 4
            CLD
            REP  MOVSD

        ; 32-byte key = the passphrase repeated until 32 bytes are filled
            XOR  esi, esi                       ; key index
            XOR  ecx, ecx                       ; bytes stored so far

        fillKey:
            MOV  al, keyBuffer[esi]
            CMP  al, 0                          ; end of passphrase?
            JNE  storeKeyByte
            XOR  esi, esi                       ; wrap around
            MOV  al, keyBuffer[esi]

        storeKeyByte:
            MOV  chachaKey[ecx], al
            INC  esi
            INC  ecx
            CMP  ecx, 32
            JB   fillKey

        ; words 4-11: the key
            MOV  esi, OFFSET chachaKey
            MOV  edi, OFFSET chachaState
            ADD  edi, 16
            MOV  ecx, 8
            REP  MOVSD

        ; word 12: block counter (starts at 1), words 13-15: nonce (all zero)
            MOV  chachaState[12 * 4], 1
            MOV  chachaState[13 * 4], 0
            MOV  chachaState[14 * 4], 0
            MOV  chachaState[15 * 4], 0

        RET

    chachaInit ENDP


    ; runs 20 rounds on chachaState and leaves the 64-byte keystream block in chachaWork
    chachaBlock PROC USES eax ebx ecx edx esi edi

        ; working copy of the state
            MOV  esi, OFFSET chachaState
            MOV  edi, OFFSET chachaWork
            MOV  ecx, 16
            CLD
            REP  MOVSD

            MOV  esi, 10                        ; 10 double rounds = 20 rounds

        doubleRound:
            ; column rounds
                chachaQR 0, 4, 8,  12
                chachaQR 1, 5, 9,  13
                chachaQR 2, 6, 10, 14
                chachaQR 3, 7, 11, 15
            ; diagonal rounds
                chachaQR 0, 5, 10, 15
                chachaQR 1, 6, 11, 12
                chachaQR 2, 7, 8,  13
                chachaQR 3, 4, 9,  14

            DEC  esi
            JNZ  doubleRound

        ; add the original state to the result
            XOR  ecx, ecx

        addState:
            MOV  eax, chachaState[ecx * 4]
            ADD  chachaWork[ecx * 4], eax
            INC  ecx
            CMP  ecx, 16
            JB   addState

        RET

    chachaBlock ENDP


    ; XORs the ChaCha20 keystream into dataBuffer (same routine for both directions)
    chachaTransform PROC USES eax ebx ecx edx esi edi

        CALL chachaInit

        MOV  esi, OFFSET dataBuffer             ; current data byte
        MOV  ecx, bytesRead                     ; bytes still to process

        blockLoop:
            CMP  ecx, 0
            JE   transformDone

            CALL chachaBlock                    ; next 64 keystream bytes -> chachaWork

            MOV  ebx, 64                        ; bytes to use from this block = min(64, ecx)
            CMP  ecx, ebx
            JAE  useBlock
            MOV  ebx, ecx

        useBlock:
            XOR  edx, edx                       ; index inside the keystream block

        xorLoop:
            MOV  al, BYTE PTR chachaWork[edx]
            XOR  [esi], al
            INC  esi
            INC  edx
            CMP  edx, ebx
            JB   xorLoop

            SUB  ecx, ebx
            INC  chachaState[12 * 4]            ; next block counter
            JMP  blockLoop

        transformDone:
            RET

    chachaTransform ENDP


    encrypt_ChaCha20Cipher PROC

        CALL chachaTransform

        RET

    encrypt_ChaCha20Cipher ENDP


    decrypt_ChaCha20Cipher PROC

        CALL chachaTransform

        RET

    decrypt_ChaCha20Cipher ENDP