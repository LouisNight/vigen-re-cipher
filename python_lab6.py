encrypted_list = []
key_list = []
current_key_index = 0


def vigenere_sq():
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    square = []

    header_row = '|   | ' + ' | '.join(alphabet) + ' |'
    separator = '|---' + '|---' * len(alphabet) + '|'

    print(header_row)
    print(separator)

    for i in range(len(alphabet)):
        row = alphabet[i:] + alphabet[:i]
        square.append(list(row))
        print(f'| {alphabet[i]} | ' + ' | '.join(row) + ' |')

    return square


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
    key = key.upper()
    plaintext = plaintext.upper()
    ciphertext = []

    key_length = len(key)

    for i, letter in enumerate(plaintext):
        if letter in alphabet:
            key_letter = key[i % key_length]
            cipher_letter = vigenere_index(key_letter, letter, alphabet)
            ciphertext.append(cipher_letter)
        else:
            ciphertext.append(letter)

    return ''.join(ciphertext)


def undo_vigenere_index(key_letter, cipher_letter, alphabet):
    key_index = letter_to_index(key_letter, alphabet)
    cipher_index = letter_to_index(cipher_letter, alphabet)
    plaintext_index = (cipher_index - key_index) % len(alphabet)
    return index_to_letter(plaintext_index, alphabet)


def decrypt_vigenere(key, cipher_text, alphabet):
    key = key.upper()
    cipher_text = cipher_text.upper()
    plaintext = []

    key_length = len(key)

    for i, cipher_letter in enumerate(cipher_text):
        if cipher_letter in alphabet:
            key_letter = key[i % key_length]
            plain_letter = undo_vigenere_index(key_letter, cipher_letter, alphabet)
            plaintext.append(plain_letter)
        else:
            plaintext.append(cipher_letter)

    return ''.join(plaintext)


# BONUS
def rotate_key():
    global current_key_index
    if not key_list:
        print("No keys available. Please add keys first.")
        return None

    key = key_list[current_key_index]
    current_key_index = (current_key_index + 1) % len(key_list)
    return key


def main_menu():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    menu_options = [
        ["Add Keys", add_keys],
        ["Encrypt", encrypt_menu],
        ["Decrypt", decrypt_menu],
        ["View Encrypted Text", dump_encrypted],
        ["Exit", exit]
    ]

    while True:
        print("\nMenu:")
        for i, option in enumerate(menu_options, 1):
            print(f"{i}. {option[0]}")

        choice = input("Please choose an option (1/2/3/4/5): ")

        if choice.isdigit() and 1 <= int(choice) <= len(menu_options):
            menu_options[int(choice) - 1][1]()
        else:
            print("Invalid choice, please try again.")


def add_keys():
    keys_input = input("Enter multiple keys separated by commas: ").upper()
    keys = [key.strip() for key in keys_input.split(',')]
    global key_list
    key_list = keys
    print(f"Keys added: {key_list}")


def encrypt_menu():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if not key_list:
        print("No keys available. Please add keys first.")
    else:
        plaintext = input("Enter the plain text: ").upper()
        key = rotate_key()
        if key:
            encrypted_text = encrypt_vigenere(key, plaintext, alphabet)
            encrypted_list.append(encrypted_text)
            print(f"Encrypted Text with key '{key}': {encrypted_text}")


def decrypt_menu():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if not encrypted_list:
        print("No encrypted text available.")
    else:
        if not key_list:
            print("No keys available. Please add keys first.")
        else:
            cipher_text = input("Enter the cipher text: ").upper()
            key = rotate_key()
            if key:
                decrypted_text = decrypt_vigenere(key, cipher_text, alphabet)
                print(f"Decrypted Text with key '{key}': {decrypted_text}")


def dump_encrypted():
    if not encrypted_list:
        print("No encrypted text available.")
    else:
        for text in encrypted_list:
            print(f"Encrypted: {text}")


main_menu()
