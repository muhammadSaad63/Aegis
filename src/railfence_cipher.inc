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

