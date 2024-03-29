#ch9_encrypt_blob.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import zlib
import base64
import datetime

filename = input('Please type the filename: ')
print ('Encrypting...')

start_enc = datetime.datetime.now()
#Our Encryption Function
def encrypt_blob(blob, public_key):
    #Import the Public Key and use for encryption using PKCS1_OAEP
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)
    #compress the data first
    blob = zlib.compress(blob)

    #In determining the chunk size, determine the private key length used in bytes
    #and subtract 42 bytes (when using PKCS1_OAEP). The data will be in encrypted
    #in chunks
    chunk_size = 470
    offset = 0
    end_loop = False
    encrypted =b""

    while not end_loop:
        #The chunk
        chunk = blob[offset:offset + chunk_size]

        #If the data chunk is less then the chunk size, then we need to add
        #padding with " ". This indicates the we reached the end of the file
        #so we end loop here
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk +=b" " * (chunk_size - len(chunk))

        #Append the encrypted chunk to the overall encrypted file
        encrypted += rsa_key.encrypt(chunk)
        
        #Increase the offset by chunk size
        offset += chunk_size

    #Base 64 encode the encrypted file
    return base64.b64encode(encrypted)

#Use the public key for encryption
fd = open("public_key.pem", "rb")
public_key = fd.read()
fd.close()

#Our candidate file to be encrypted
fd = open(filename, "rb")
unencrypted_blob = fd.read()
fd.close()

encrypted_blob = encrypt_blob(unencrypted_blob, public_key)

#Write the encrypted contents to a file
fd = open(filename + ".enc", "wb")
fd.write(encrypted_blob)
fd.close()

end_enc = datetime.datetime.now()
elapsed_enc = end_enc - start_enc

print ('Encryption is finished...')
print ('Execution Time of Encryption: ', elapsed_enc, ' Hour:Minute:Second')
print ('Decrypting...')

start_dec = datetime.datetime.now()

def decrypt_blob(encrypted_blob, private_key):

    #Import the Private Key and use for decryption using PKCS1_OAEP
    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)

    #Base 64 decode the data
    encrypted_blob = base64.b64decode(encrypted_blob)

    #In determining the chunk size, determine the private key length used in bytes.
    #The data will be in decrypted in chunks
    chunk_size = 512
    offset = 0
    decrypted =b""

    #keep loop going as long as we have chunks to decrypt
    while offset < len(encrypted_blob):
        #The chunk
        chunk = encrypted_blob[offset: offset + chunk_size]

        #Append the decrypted chunk to the overall decrypted file
        decrypted += rsakey.decrypt(chunk)

        #Increase the offset by chunk size
        offset += chunk_size

    #return the decompressed decrypted data
    return zlib.decompress(decrypted)

#Use the private key for decryption
fd = open("private_key.pem", "rb")
private_key = fd.read()
fd.close()

#Our candidate file to be decrypted
fd = open(filename +'.enc', "rb")
encrypted_blob = fd.read()
fd.close()

#Write the decrypted contents to a file
fd = open(filename + '.dec', "wb")
fd.write(decrypt_blob(encrypted_blob, private_key))
fd.close()

end_dec = datetime.datetime.now()
elapsed_dec = end_dec - start_dec

print ('Decryipting is done...')
print ('Execution Time of Encryption: ', elapsed_dec, ' Hour:Minute:Second')
