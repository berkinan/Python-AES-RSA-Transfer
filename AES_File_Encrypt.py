from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode , b64decode
import datetime

filename = input('Please type the filename: ')
key_file = input('Please enter the key to encrypt: ')

fd = open(key_file, "r")
key = fd.read()
fd.close()

print ('Encrypting...')

start_enc = datetime.datetime.now()

key = key.encode('UTF-8')
key = pad(key,AES.block_size)

def encrypt (file_name,key):
    with open (file_name,'rb') as entry:
        data = entry.read()
        cipher = AES.new(key,AES.MODE_CFB)
        ciphertext = cipher.encrypt(pad(data,AES.block_size))
        iv = b64encode(cipher.iv).decode('UTF-8')
        ciphertext = b64encode(ciphertext).decode('UTF-8')
        to_write = iv + ciphertext
    entry.close()
    with open(file_name+'.enc', 'w') as data:
        data.write(to_write)
    data.close()

encrypt(filename,key)

end_enc = datetime.datetime.now()
elapsed_enc = end_enc - start_enc

print ('Encrypting is done...')
print ('Execution Time of Encryption: ', elapsed_enc, ' Hour:Minute:Second')

key_file = input('Please enter the key to decrypt: ')

start_dec = datetime.datetime.now()

fd = open(key_file, "r")
key = fd.read()
fd.close()
key = key.encode('UTF-8')
key = pad(key,AES.block_size)

with open (filename + '.enc', 'r') as entry:
    try:
        print ('Decrypting...')

        data = entry.read()
        length = len(data)
        iv = data[:24]
        iv = b64decode(iv)
        ciphertext = data[24:length]
        ciphertext = b64decode(ciphertext)
        cipher = AES.new(key,AES.MODE_CFB,iv)
        decrypted = cipher.decrypt(ciphertext)
        decrypted = unpad(decrypted,AES.block_size)
        with open (filename + '.dcp', 'wb') as data:
            data.write(decrypted)
        data.close()

        print ('Decryipting is done...')

        end_dec = datetime.datetime.now()
        elapsed_dec = end_dec - start_dec

        print ('Execution Time of Encryption: ', elapsed_dec, ' Hour:Minute:Second')
    except(ValueError,KeyError):
        print('Wrong Password')