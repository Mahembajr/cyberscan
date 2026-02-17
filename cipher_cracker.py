#!/usr/bin/env python3
"""
======================================
  CipherCrack - Cipher Cracker Tool
  Phase 1 Cybersecurity Portfolio Project
======================================
"""

from collections import Counter

# ─────────────────────────────────────────
#  ENGLISH LANGUAGE DATA
# ─────────────────────────────────────────

ENGLISH_WORDS = [
    'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that',
    'have', 'it', 'for', 'not', 'on', 'with', 'he', 'as',
    'you', 'do', 'at', 'this', 'but', 'his', 'by', 'from',
    'hello', 'world', 'secret', 'message', 'attack', 'security',
    'system', 'key', 'cipher', 'encrypt', 'decrypt', 'quick',
    'brown', 'fox', 'jumps', 'over', 'lazy', 'dog', 'are',
    'was', 'is', 'we', 'they', 'all', 'one', 'has', 'her'
]

LETTER_FREQ = {
    'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
    'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3,
    'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.4, 'w': 2.4,
    'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5,
    'v': 1.0, 'k': 0.8, 'j': 0.2, 'x': 0.2, 'q': 0.1, 'z': 0.1
}

# ─────────────────────────────────────────
#  CAESAR CIPHER
# ─────────────────────────────────────────

def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def score_text(text):
    words = text.lower().split()
    return sum(1 for word in words if word in ENGLISH_WORDS)

def caesar_brute_force(ciphertext):
    print("\n--- BRUTE FORCE RESULTS ---")
    best_score = 0
    best_result = None

    for shift in range(1, 26):
        attempt = caesar_decrypt(ciphertext, shift)
        score = score_text(attempt)
        print(f"  Shift {shift:2d}: {attempt}  (score: {score})")

        if score > best_score:
            best_score = score
            best_result = (shift, attempt)

    if best_result:
        print(f"\n  [+] Most likely decryption -> Shift {best_result[0]}: {best_result[1]}")
    return best_result

# ─────────────────────────────────────────
#  VIGENERE CIPHER
# ─────────────────────────────────────────

def vigenere_encrypt(text, key):
    result = ""
    key = key.upper()
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    result = ""
    key = key.upper()
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result

def find_key_length(ciphertext):
    text = ''.join(c.lower() for c in ciphertext if c.isalpha())
    scores = {}
    for key_len in range(2, 10):
        score = 0
        for i in range(key_len):
            column = text[i::key_len]
            freq = Counter(column)
            n = len(column)
            if n > 1:
                ic = sum(f * (f-1) for f in freq.values()) / (n * (n-1))
                score += ic
        scores[key_len] = score / key_len
    best_len = max(scores, key=scores.get)
    return best_len, scores

def crack_vigenere(ciphertext):
    print("\n--- VIGENERE CRACKER ---")
    text = ''.join(c.lower() for c in ciphertext if c.isalpha())

    if len(text) < 40:
        print("  [!] Warning: text is short -- cracking works best with 100+ characters")

    key_len, scores = find_key_length(ciphertext)
    print(f"[*] Testing key lengths 2-9...")
    for l, s in sorted(scores.items()):
        bar = 'X' * int(s * 500)
        print(f"    Length {l}: {bar} ({s:.4f})")
    print(f"[+] Most likely key length: {key_len}")

    key = ""
    for i in range(key_len):
        column = text[i::key_len]
        best_shift = 0
        best_score = -1
        for shift in range(26):
            score = 0
            for char in column:
                decrypted_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
                score += LETTER_FREQ.get(decrypted_char, 0)
            if score > best_score:
                best_score = score
                best_shift = shift
        key += chr(best_shift + ord('A'))

    print(f"[+] Recovered key: {key}")
    decrypted = vigenere_decrypt(ciphertext, key)
    print(f"[+] Decrypted text: {decrypted}")
    return key, decrypted

# ─────────────────────────────────────────
#  MENU
# ─────────────────────────────────────────

def print_menu():
    print("\n" + "="*55)
    print("  CIPHERCRACK -- Cipher Cracker Tool")
    print("  Phase 1 Cybersecurity Portfolio Project")
    print("="*55)
    print("  CAESAR CIPHER")
    print("  1. Encrypt a message")
    print("  2. Decrypt a message")
    print("  3. Brute force crack (no key needed)")
    print()
    print("  VIGENERE CIPHER")
    print("  4. Encrypt a message")
    print("  5. Decrypt a message")
    print("  6. Crack (no key needed)")
    print()
    print("  7. Exit")
    print("="*55)

def main():
    while True:
        print_menu()
        choice = input("\n  Select option (1-7): ").strip()

        if choice == "1":
            text = input("\n  Enter message: ")
            shift = int(input("  Enter shift (1-25): "))
            result = caesar_encrypt(text, shift)
            print(f"\n  [+] Encrypted: {result}")

        elif choice == "2":
            text = input("\n  Enter ciphertext: ")
            shift = int(input("  Enter shift (1-25): "))
            result = caesar_decrypt(text, shift)
            print(f"\n  [+] Decrypted: {result}")

        elif choice == "3":
            text = input("\n  Enter ciphertext to crack: ")
            caesar_brute_force(text)

        elif choice == "4":
            text = input("\n  Enter message: ")
            key = input("  Enter keyword: ")
            result = vigenere_encrypt(text, key)
            print(f"\n  [+] Encrypted: {result}")

        elif choice == "5":
            text = input("\n  Enter ciphertext: ")
            key = input("  Enter keyword: ")
            result = vigenere_decrypt(text, key)
            print(f"\n  [+] Decrypted: {result}")

        elif choice == "6":
            text = input("\n  Enter ciphertext to crack: ")
            crack_vigenere(text)

        elif choice == "7":
            print("\n  Goodbye!\n")
            break

        else:
            print("\n  [!] Invalid option -- choose 1 to 7")

        input("\n  Press Enter to continue...")

if __name__ == "__main__":
    main()
7