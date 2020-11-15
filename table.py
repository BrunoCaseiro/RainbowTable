import random, os, sys, copy, time, math, hashlib, textwrap
from cryptography.hazmat.primitives import padding, hashes, keywrap
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.backends import default_backend


def table(length, size, filename):
    size = int(size)
    length = int(length)
    InputsZero = 2**size
    k = math.floor(math.pow(64, length)/math.pow(2, size))                 # For 100% chance (all 64^l passwords) -> 64^l = 2^s * k <=> k = 64^l/2^s

    rainbow = generateRain(length, InputsZero) 
    line = 0
    for x in rainbow:
        for i in range(0, k-1):
            print("ENCRYPTING::: ", x[1])
            x[1] = encrypt(bytes(x[1], 'UTF-8'))                     # first column is left untouched            

            print("REDUCING::::: ", x[1])
            x[1] = reduct(length, x[1], i)         # cipher and reduction is done on second column, only last hash is saved


        x[1] = encrypt(bytes(x[1],'UTF-8'))                          # This makes the last column encrypted 
        line +=1
        
    printRainbow(rainbow, filename, length, k)
    return


def reduct(length, hashData, k):
    charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?"              # 64 chars
    mapping = []
    for char in charSet:
        mapping.append(char)

    pwd = ""

    shaHash = hashlib.sha1(hashData.encode()).hexdigest()
    shaHash = textwrap.wrap(shaHash, length)
    
    while len(pwd) != length:   
        pwdChar = (( int(shaHash[0], 16) + int(shaHash[1],16) )+(k+1)*16603) % 64
        shaHash = shaHash[2:]
        pwd += mapping[pwdChar]
    return pwd


def encrypt(data):                                                           
    # Repeats input until 16 bytes. If past 16 bytes, cuts rest out. This will be the AES key
    
    key = data
    while(len(key) < 16):
        key += data
    key = key[0:16]


    # Sets up cipher
    cipher = Cipher(algorithms.AES(key), modes.ECB(), default_backend())	
    ctx = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size//8).padder()
    
    # Actual encryption
    ciphertext = ctx.update(padder.update(key) + padder.finalize())

    # Decryption (verification)
    #decryptor = cipher.decryptor()
    #text = decryptor.update(ciphertext) + decryptor.finalize()
    #unpadder = padding.PKCS7(algorithms.AES.block_size//8).unpadder()
    #text = unpadder.update(text) + unpadder.finalize()
    #print(text)


    return ciphertext.hex()


def generateRain(length, dicEntries):                                            # Creates 2D array, rainbow[x][0] has inputs, rainbow[x][1] WILL HAVE hashes

    rainbow = [[0 for x in range(2)] for y in range(dicEntries)]
    
    charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?"
    word = ''.join((random.choice(charSet) for i in range(length)))

    for i in range(dicEntries):                                                 
        if any(bytes(word, 'UTF-8') in input for input in rainbow):                     # Avoiding duplicates
            word = ''.join((random.choice(charSet) for i in range(length)))
        rainbow[i][0] = bytes(word, 'UTF-8')
        rainbow[i][1] = word


    return rainbow


def printRainbow(rainbow, filename, length, k):                  # save the first and last column of the rainbow table to file. In the end saves length of pwds and chains
    f = open(filename, "a")
    f.write("INPUTS           HASH\n")
    
    for x in rainbow:
        f.write((str(x[0]) + "           " + str(x[1]) + "\n"))

    f.write(str(length) + " " + str(k))
    f.close()

    print("\n\nRAINBOW TABLE SAVED TO FILE " + filename + ".txt")


st = time.time()

print(encrypt(bytes("Em?q",'utf-8')))
if(len(sys.argv) != 4) :
    print("USAGE: python3 table.py length size filename")
else:
    table(sys.argv[1], sys.argv[2], sys.argv[3])
    print("\n It took ", (time.time() - st), " seconds to generate the table")