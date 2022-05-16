from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

file_path = input('File path: ')

with open(file_path, 'rb') as input_file:
    file_bytes = input_file.read()

    key = get_random_bytes(16)
    print('The used key is ', key)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file_bytes)

    file_out = open("encrypted.wav", "wb")
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
    file_out.close()


    file_in = open("encrypted.wav", "rb")
    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

    # let's assume that the key is somehow available again
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    file_out = open("decrypted.wav", "wb")
    file_out.write(data)
    file_out.close()
