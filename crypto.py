ASCII_LETTER_START = 65
LENGTH_ALPHABET = 26

# Caesar Cipher
# Arguments: string, integer
# Returns: string
def encrypt_caesar(plaintext, offset):
    new_text = ""
    for letter in plaintext.upper():
        if letter.isalpha():
            numLetter = ord(letter) - ASCII_LETTER_START
            offsetNumLetter = (numLetter + offset)%LENGTH_ALPHABET
            letter = chr(offsetNumLetter + ASCII_LETTER_START)
        new_text += letter
    return new_text

# Arguments: string, integer
# Returns: string
def decrypt_caesar(ciphertext, offset):
    new_text = ""
    for letter in ciphertext.upper():
        if letter.isalpha():
            numLetter = ord(letter) - ASCII_LETTER_START
            offsetNumLetter = (numLetter - offset)%LENGTH_ALPHABET
            letter = chr(offsetNumLetter + ASCII_LETTER_START)
        new_text += letter
    return new_text

# Vigenere Cipher
# Arguments: string, string
# Returns: string
def encrypt_vigenere(plaintext, keyword):
    new_text = ""
    keyword=keyword.upper()
    plaintext=plaintext.upper()
    for index,letter in enumerate(plaintext):
        offset = ord(keyword[index%len(keyword)]) - ASCII_LETTER_START
        if letter.isalpha():
            numLetter = ord(letter) - ASCII_LETTER_START
            offsetNumLetter = (numLetter + offset)%LENGTH_ALPHABET
            letter = chr(offsetNumLetter + ASCII_LETTER_START)
        new_text += letter
    return new_text

# Arguments: string, string
# Returns: string
def decrypt_vigenere(ciphertext, keyword):
    new_text = ""
    keyword=keyword.upper()
    ciphertext=ciphertext.upper()
    for index,letter in enumerate(ciphertext):
        offset = ord(keyword[index%len(keyword)]) - ASCII_LETTER_START
        if letter.isalpha():
            numLetter = ord(letter) - ASCII_LETTER_START
            offsetNumLetter = (numLetter - offset)%LENGTH_ALPHABET
            letter = chr(offsetNumLetter + ASCII_LETTER_START)
        new_text += letter
    return new_text
# Merkle-Hellman Knapsack Cryptosystem
# Arguments: integer
# Returns: tuple (W, Q, R) - W a length-n tuple of integers, Q and R both integers
def generate_private_key(n=8):
    
    pass

# Arguments: tuple (W, Q, R) - W a length-n tuple of integers, Q and R both integers
# Returns: tuple B - a length-n tuple of integers
def create_public_key(private_key):
    pass

# Arguments: string, tuple (W, Q, R)
# Returns: list of integers
def encrypt_mhkc(plaintext, public_key):
    pass

# Arguments: list of integers, tuple B - a length-n tuple of integers
# Returns: bytearray or str of plaintext
def decrypt_mhkc(ciphertext, private_key):
    pass

def main():
    print(decrypt_vigenere(input(),input()))
    pass

if __name__ == "__main__":
    main()
