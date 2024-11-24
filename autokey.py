def generate_key(plaintext, keyword): """ Generates 
    the full key by combining the keyword with the 
    plaintext. If the keyword is shorter than the 
    plaintext, we repeat the plaintext as key. """
    # Combine keyword and plaintext, starting from the 
    # end of the keyword
    key = keyword + plaintext return 
    key[:len(plaintext)] # Key must be the same length 
    as the plaintext


def autokey_encrypt(plaintext, keyword): """ Encrypts 
    the plaintext using the Autokey cipher. Each 
    letter of the plaintext is shifted based on the 
    corresponding letter in the key. """ plaintext = 
    plaintext.upper().replace(" ", "") # Make 
    plaintext uppercase and remove spaces keyword = 
    keyword.upper().replace(" ", "") # Make keyword 
    uppercase and remove spaces ciphertext = []

    # Generate the key using the plaintext and the 
    # keyword
    key = generate_key(plaintext, keyword)

    # Encrypt each character
    for i in range(len(plaintext)): plain_char = 
        plaintext[i] key_char = key[i]
        
        # Calculate the shift for the current 
        # character
        shift = ord(key_char) - ord('A')
        
        # Encrypt the character using the Autokey 
        # cipher formula
        cipher_char = chr((ord(plain_char) - ord('A') 
        + shift) % 26 + ord('A')) 
        ciphertext.append(cipher_char)

    return ''.join(ciphertext)


def autokey_decrypt(ciphertext, keyword): """ Decrypts 
    the ciphertext using the Autokey cipher. Each 
    letter of the ciphertext is shifted back based on 
    the corresponding letter in the key. """ 
    ciphertext = ciphertext.upper().replace(" ", "") # 
    Make ciphertext uppercase and remove spaces 
    keyword = keyword.upper().replace(" ", "") # Make 
    keyword uppercase and remove spaces plaintext = []

    # Generate the key using the ciphertext and the 
    # keyword
    key = generate_key(ciphertext, keyword)

    # Decrypt each character
    for i in range(len(ciphertext)): cipher_char = 
        ciphertext[i] key_char = key[i]

        # Calculate the shift for the current 
        # character
        shift = ord(key_char) - ord('A')
        
        # Decrypt the character using the Autokey 
        # cipher formula
        plain_char = chr((ord(cipher_char) - ord('A') 
        - shift) % 26 + ord('A')) 
        plaintext.append(plain_char)

        # The key shifts forward by adding the 
        # decrypted character to it
        key += plain_char

    return ''.join(plaintext)


# Example usage
if __name__ == "__main__": plaintext = "HELLO" keyword 
    = "KEY"

    print("Original Plaintext: ", plaintext)
    
    # Encrypt the plaintext
    encrypted_text = autokey_encrypt(plaintext, 
    keyword) print("Encrypted Text: ", encrypted_text)

    # Decrypt the ciphertext
    decrypted_text = autokey_decrypt(encrypted_text, 
    keyword) print("Decrypted Text: ", decrypted_text)
