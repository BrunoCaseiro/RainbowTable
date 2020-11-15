import os, sys, copy, hashlib, textwrap
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.backends import default_backend



def guess(filename, hashedPassword):
    count = 0
    # Reading file and saving pwd length and max k
    with open(filename, "r") as file:
        last_line = file.readline()
        for last_line in file:
            pass

    last_line = last_line.split(" ")
    pwdLength = int(last_line[0])
    chainLength = int(last_line[1])

    # Opening rainbow file, 
    rainbow = open(filename, "r")
    lines = rainbow.readlines()[1:-1]

    # First check all hashes already on rainbow table
    for line in lines:
        line = line.split(" ", 1)
        pwd = line[0][2:-1]
        hashData = line[1].strip()

        print("Comparing to: ", hashData, "of last column")
        if (hashData == hashedPassword):
            for i in range(0, chainLength-1):
                pwd = encrypt(bytes(pwd, 'UTF-8'))                
                count += 1
                pwd = reduct(pwdLength, pwd, i)

            print("PASSWORD CRACKED::::: ", pwd, "\n")
            print("AES Operations: ", count)
            sys.exit()
            
    # If not found, search the full table
    for line in lines:
        line = line.split(" ", 1)
        pwd = line[0][2:-1]

        for i in range(0, chainLength-1):
            pwdTwo = encrypt(bytes(pwd, 'UTF-8'))
            count += 1

            print("Comparing to: ", pwdTwo)
            if (pwdTwo == hashedPassword):
                print("PASSWORD CRACKED::::: ", pwd, "\n")
                print("AES Operations: ", count)
                sys.exit()
            else:
                pwdTwo = reduct(pwdLength, pwdTwo, i)
                pwd = copy.deepcopy(pwdTwo)
            
   
    print("Password not found\n")
    print("AES Operations: ", count)


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
    #unpadder = padding.PKCS7(128).unpadder()
    #text = unpadder.update(text) + unpadder.finalize()
    #print(text)


    return ciphertext.hex()

if(len(sys.argv) != 3) :
    print("USAGE: python3 guess.py filename hash")
else:
    guess(sys.argv[1], sys.argv[2])