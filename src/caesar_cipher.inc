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