def vigenere_sq():
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

    header_row = '|   | ' + ' | '.join(alphabet) + ' |'
    separator = '|---' + '|---' * len(alphabet) + '|'

    print(header_row)
    print(separator)

    for i in range(len(alphabet)):
        row_letter = alphabet[i]
        row = alphabet[i:] + alphabet[:i]
        print(f'| {row_letter} | ' + ' | '.join(row) + ' |')

vigenere_sq()

def letter_to_index(letter, alphabet):
    return alphabet.index(letter)

def index_to_letter(index, alphabet):
    return alphabet[index % len(alphabet)]

def vigenere_index(key_letter, plaintext_letter, alphabet):
    key_index = letter_to_index(key_letter, alphabet)
    plaintext_index = letter_to_index(plaintext_letter, alphabet)
    cipher_index = (plaintext_index + key_index) % len(alphabet)
    return index_to_letter(cipher_index, alphabet)

def encrypt_vigenere(key, plaintext, alphabet):
    ciphertext = []
    key_length = len(key)

    for i, letter in enumerate(plaintext):
        key_letter = key[i % key_length]
        cipher_letter = vigenere_index(key_letter, letter, alphabet)
        ciphertext.append(cipher_letter)

    return ''.join(ciphertext)

def undo_vigenere_index(key_letter, cipher_letter, alphabet):
    key_index = letter_to_index(key_letter, alphabet)
    cipher_index = letter_to_index(cipher_letter, alphabet)
    plaintext_index = (cipher_index - key_index) % len(alphabet)
    return index_to_letter(plaintext_index, alphabet)

def decrypt_vigenere(key, cipher_text, alphabet):
    plaintext = []
    key_length = len(key)

    for i, cipher_letter in enumerate(cipher_text):
        key_letter = key[i % key_length]
        plain_letter = undo_vigenere_index(key_letter, cipher_letter, alphabet)
        plaintext.append(plain_letter)

    return ''.join(plaintext)

def main_menu():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = input("Enter the encryption/decryption key: ").upper()

    while True:
        print("\nMenu:")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")

        choice = input("Please choose an option (1/2/3): ")

        if choice == '1':
            # ENCRYPT
            plaintext = input("Enter the plain text: ").upper()
            encrypted_text = encrypt_vigenere(key, plaintext, alphabet)
            print(f"Encrypted Text: {encrypted_text}")

        elif choice == '2':
            # DECRYPT
            cipher_text = input("Enter the cipher text: ").upper()
            decrypted_text = decrypt_vigenere(key, cipher_text, alphabet)
            print(f"Decrypted Text: {decrypted_text}")

        elif choice == '3':
            print("Exiting...")
            break

        else:
            print("Invalid choice, please choose 1, 2, or 3.")

main_menu()

