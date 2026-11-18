; RC4 KSA (Key-Scheduling Algorithm)
    rc4KSA PROC
        PUSHad
        XOR ecx, ecx

        initSBoxLoop:
            MOV rc4State[ecx], cl
            INC ecx
            CMP ecx, 256
            JL  initSBoxLoop

            XOR ecx, ecx            
            XOR ebx, ebx            
            XOR edx, edx            
            
        ksaLoop:
            MOV al, rc4State[ecx]   
            
            PUSH ecx
            MOV esi, OFFSET keyBuffer
            ADD esi, edx            
            MOV ah, [esi]           
            CMP ah, 0               
            JNE keyValid
            
            XOR edx, edx
            MOV esi, OFFSET keyBuffer
            MOV ah, [esi]
        keyValid:
            POP ecx

            ADD bl, al              
            ADD bl, ah              

            MOV al, rc4State[ecx]   
            
            PUSH ecx
            MOVzx ecx, bl           
            MOV ah, rc4State[ecx]   
            POP ecx                 

            MOV rc4State[ecx], ah   
            
            PUSH ecx
            MOVzx ecx, bl
            MOV rc4State[ecx], al   
            POP ecx

            INC edx                 
            INC ecx                 
            CMP ecx, 256
            JL  ksaLoop

        POPad
        RET

    rc4KSA ENDP


    ; RC4 PRGA & Stream Transformation
    rc4Transform PROC
        PUSHad

        CALL rc4KSA

        XOR ecx, ecx            
        XOR esi, esi            
        MOV bl, 0               
        MOV bh, 0               

        prgaLoop:
            CMP ecx, bytesRead      
            JGE prgaDone

            INC bl                  
            
            PUSH ecx
            MOVzx ecx, bl
            MOV al, rc4State[ecx]   
            POP ecx
            
            ADD bh, al              

            PUSH ecx
            MOVzx ecx, bl
            MOV al, rc4State[ecx]   
            
            PUSH ebx
            MOVzx ecx, bh           
            MOV ah, rc4State[ecx]   
            POP ebx

            MOV rc4State[ecx], al   
            
            PUSH ebx
            MOVzx ecx, bl           
            MOV rc4State[ecx], ah   
            POP ebx
            
            POP ecx

            PUSH ecx
            MOVzx ecx, bl
            MOV al, rc4State[ecx]   
            MOVzx ecx, bh
            MOV ah, rc4State[ecx]   
            POP ecx

            ADD al, ah              
            MOVzx edx, al           
            MOV al, rc4State[edx]   

            MOV esi, OFFSET dataBuffer
            ADD esi, ecx            
            XOR [esi], al           

            INC ecx                 
            JMP prgaLoop

        prgaDone:
            POPad
            RET

    rc4Transform ENDP


    ; medium
    encrypt_RC4Cipher PROC

        CALL rc4Transform
        
        RET

    encrypt_RC4Cipher ENDP


    decrypt_RC4Cipher PROC

        CALL rc4Transform

        RET

    decrypt_RC4Cipher ENDP

