# 🛡️ Aegis

**Aegis** is a lightweight, bare-metal file encryption and security utility built entirely from scratch in pure **Assembly**. Designed for maximum performance and a microscopic memory footprint, it operates directly close to the hardware to secure files without runtime bloat or external dependencies.

---
<br>

<br>

## ✨ Key Architectural Highlights

* **Pure Assembly Core**: Built without high-level runtime abstractions, leveraging raw registers, direct system calls, and optimized bitwise/byte transformations.
* **Zero Dependencies**: Requires no external cryptographic libraries, dynamic linkers, or heavy runtimes—making it fully self-contained and auditable down to the instruction set.
* **Blazing Fast Execution**: Designed for instant stream processing, minimal CPU overhead, and optimal cache utilization.
* **Low-Level Precision**: Implements direct file I/O buffering and precise byte manipulation for rapid encryption and decryption pipelines.

<br>

## 🚀 Why Assembly?

While most modern cryptography tools rely on high-level languages, **Aegis** is an exercise in absolute hardware control. By managing memory allocation, stack frames, and bit operations manually at the instruction level, it demonstrates foundational systems-engineering principles, reverse-engineering resilience, and deep computer architecture mastery.



Algorithm 1: Repeating-Key XOR Cipher
What It Is

The XOR (Exclusive OR) cipher is a symmetric stream cipher. It relies on the mathematical property that if you XOR a piece of data with a key, you get ciphertext; if you XOR that ciphertext with the exact same key, it reverts back to the original plaintext.

Because of this symmetry, the exact same routine handles both encryption and decryption.
Inputs & Outputs

    Inputs:

        A data chunk loaded into memory (dataBuffer).

        A key or passphrase (keyBuffer).

    Outputs:

        The modified data buffer overwritten in place with the XOR-transformed bytes, ready to be written to the output file.

What It Expects

    A valid file handle containing data to read.

    A key string entered by the user (if the user enters a multi-character passphrase, the cipher will cycle through the characters sequentially).

    A loop counter matching the exact number of bytes read (bytesRead) from the current file chunk.

What It Does (Step-by-Step Logic)

    Pointers Setup: Sets ESI to point to the start of the data buffer and initializes a key index tracker (EDI = 0).

    Byte Retrieval: Grabs the current byte from the key buffer (keyBuffer[edi]).

    Null Check & Wrap: Checks if the key byte is a null terminator (0). If it hits the end of the passphrase, it resets EDI to 0 to loop back to the start of the key (repeating-key behavior).

    Transformation: Applies the bitwise XOR instruction (xor [esi], al) directly to the data byte in memory.

    Advancement: Increments the data pointer (ESI), increments the key pointer (EDI), and decrements the chunk loop counter (ECX) until the entire buffer block is processed.


Algorithm 2: Caesar Cipher (Substitution)
What It Is

The Caesar cipher is one of the oldest and simplest substitution ciphers. It shifts each letter in the text forward (or backward) by a fixed number of positions down the alphabet. For example, with a shift of 3, A becomes D, B becomes E, and Z wraps around to C.
Inputs & Outputs

    Inputs:

        A data chunk loaded into memory (dataBuffer).

        A key or shift value (we can derive the shift amount from the user's keyBuffer, such as using the first character's ASCII value or its length).

    Outputs:

        The modified data buffer overwritten in place with the shifted characters.

What It Expects

    The Text-Only Constraint: Unlike XOR (which treats everything as raw binary bytes), the classic Caesar cipher only works on alphabetic text (A–Z and a–z).

    If you run a pure Caesar shift on a binary file (like an .exe, .jpg, or .zip), shifting raw bytes will corrupt vital file headers, null bytes, and structural markers. Therefore, a proper implementation must filter bytes, applying the shift only to valid ASCII letters and leaving numbers, symbols, and binary bytes completely untouched.

What It Does (Step-by-Step Logic)

    Pointers Setup: Points ESI to the start of dataBuffer and loads the loop counter with bytesRead.

    Byte Inspection: Grabs a single byte from the buffer and checks if it falls within the uppercase range (65 to 90 for A–Z) or lowercase range (97 to 122 for a–z).

    Conditional Branching:

        If it's not a letter, it skips the transformation and moves to the next byte.

        If it is a letter, it applies the shift value.

    Alphabet Wrap-Around: If the shift pushes a letter past Z or z (e.g., shifting Z forward by 3), math is applied to wrap it back around to the beginning of the alphabet (A or a).

    Advancement: Steps through the buffer until all bytes in the chunk are processed.



Algorithm 3: Rail Fence Cipher (Transposition)
What It Is

The Rail Fence cipher (also called a zigzag cipher) is a transposition cipher. Unlike XOR or Caesar (which substitute characters for other characters), a transposition cipher keeps the exact same characters but rearranges their positions in a zigzag pattern across multiple imaginary "rails" (rows) and then reads them off row-by-row.
Inputs & Outputs

    Inputs:

        A data chunk loaded into memory (dataBuffer).

        A key representing the number of rails (for simplicity, we can use a standard rail depth of 3, or derive it from the length/value of keyBuffer).

    Outputs:

        The rearranged data buffer (encrypted text), or reconstructed text (decrypted text).

What It Expects

    Because it rearranges byte positions, characters don't stay where they started.

    To implement a clean Rail Fence cipher within our stream architecture without overwriting data mid-calculation, it requires a temporary workspace or scratch area in memory to map the zigzag rows before writing them back to dataBuffer.

What It Does (Step-by-Step Logic)

    Row Traversal Tracking: Uses a directional flag (moving down or up) to trace a zigzag path from row 0 down to row numRails - 1 and back up.

    Matrix / Row Bucketing: Distributes each byte of the input chunk into separate logical rows based on the current rail index.

    Reconstruction: Once all characters in the chunk are sorted into their respective rails, it concatenates the rails sequentially (Row 0, then Row 1, then Row 2) back into the data buffer.