# Aegis Project Roadmap & TODO

## Day 1: Remaining Cipher Implementations
- [ ] Implement and integrate **Rail Fence Cipher** (3-rail transposition)
- [ ] Integrate **Vigenère Cipher** (Polyalphabetic substitution)
- [ ] Integrate **RC4 Cipher** (State-based stream cipher)
- [ ] Integrate **ChaCha20 Cipher** (Modern ARX block stream cipher)

## Day 2: Decryption & Mode Selection
- [ ] Add an Encrypt vs. Decrypt mode toggle in the prompt flow
- [ ] Implement **Rail Fence Decryption** (reconstructing the zigzag matrix from ciphertext)
- [ ] Validate symmetric round-trip testing for XOR, Caesar, and RC4

## Day 3: Interactive Menu & Text Mode
- [ ] Design and build a clean console **Main Menu** for cipher selection
- [ ] Implement **Direct Console Text Support** (allowing string input/output alongside file streaming)
- [ ] Route user selections cleanly to the respective cipher procedures

## Day 4: UI Polish, Colors, Animation & Win32 Integration
- [ ] Implement **animated typewriter printing** using Irvine32's `Delay` procedure for prompt banners
- [ ] Add terminal color coding using Irvine32 `SetTextColor` for success, errors, and headers
- [ ] Integrate native Win32 **`MessageBox` API calls** for critical error alerts and success popups