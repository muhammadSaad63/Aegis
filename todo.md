## 1. UX & Interface Enhancements

    [ ] "Press Enter to Continue" Flow: Implement a pause utility after executeEngine finishes and before redrawing the menu so the user has time to review output/success messages.

    [ ] Animated Banner/Printing with Delay: Integrate Irvine32's Delay macro to give a typewriter or staggered loading effect when drawing the startup banner or processing blocks.

    [ ] Advanced Color Integration: Enhance SetTextColor usage beyond static headers—for instance, color-coding warnings (red), success messages (green), active toggles, and cipher options dynamically.

    [ ] MessageBox Integration: Use Irvine32's Win32 API wrappers (MsgBox / MsgBoxAsk) for critical errors (like file read failures or invalid paths) instead of just writing text to the console.

<br>

## 2. Robust File I/O & Safety Validations

    [ ] Empty Input & File Path Validation: Implement validation checks to ensure user input paths, output paths, and console text buffers are not blank or malformed before attempting file handles or transformations.

    [ ] File Existence & Permission Checks: Verify that source files exist and can be safely opened before running stream loops, gracefully handling missing files or locked handles.

<br>

## 3. Architecture & Code Quality

    [ ] Improve Variable Names: Clean up shorthand or generic global variable names (e.g., standardizing prefixes, making buffer names and handle descriptors more descriptive).

    [ ] Modular File Split (.inc Refactoring): Split the massive single-file assembly code into logical include files (e.g., engine.inc, ciphers.inc, ui.inc) to keep the project clean and maintainable.

    [ ] CLI Arguments Utility: Add support for command-line execution flags (e.g., -e, -d, -c [1-5], -i [file], -o [file], -k [key]) alongside the interactive menu.

    [ ] Metadata Header Injection (Optional/Advanced): Embed algorithm metadata and key hints into the output file header during encryption so decryption can auto-detect them without manual user prompts.

<br>

## 4. Missing Cryptographic Implementations (Core Roadmap)

    [ ] Rail Fence Cipher (Option 3): Implement zig-zag index stride mathematics for both encrypt_RailFenceCipher and decrypt_RailFenceCipher, handling full-buffer transposition.

    [ ] Vigenère Cipher (Option 4): Implement polyalphabetic shifting modulo 26 using keyBuffer, ensuring non-alphabetic characters are skipped correctly and key indices advance appropriately.

    [ ] RC4 & ChaCha20 ARX (Option 5): Implement the stream cipher state initialization, key-scheduling algorithm (KSA), and pseudo-random generation algorithm (PRGA) / ARX blocks.