
from Crypto.Cipher import AES
string = input("Enter string to encrypt: ")
plain_text = bytes(string, 'utf-8')
#plain_text = b'Random text to encrypt here'
key = b'Sixteen byte key'
cipher = AES.new(key, AES.MODE_EAX)

nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(plain_text)

#AES Decryption
key = b'Sixteen byte key'
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
plaintext = cipher.decrypt(ciphertext)
try:
    cipher.verify(tag)
    print("The message is authentic:", plaintext)
except ValueError:
    print("Key incorrect or message corrupted")
