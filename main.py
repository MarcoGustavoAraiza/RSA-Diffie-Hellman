import random
import sys

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime
import hashlib


def FastModularExponentiation(alpha, pk, q):
    return pow(alpha, pk, q)

def genPrivateKey(q):
    return random.randint(0, q)


def alice(publickey, privatekey, q, iv):

    secretKey = FastModularExponentiation(publickey, privatekey, q)
    print(secretKey)

    key = hashlib.sha256(secretKey.to_bytes(secretKey.bit_length(), 'big'))


    cipher = AES.new(key.digest(), AES.MODE_CBC, iv)

    message = b'Hi, Bob!'
    encrypted = cipher.encrypt(pad(message, AES.block_size))

    return encrypted


def bob(publickey, privatekey, q, iv):

    secretKey = FastModularExponentiation(publickey, privatekey, q)
    print(secretKey)
    key = hashlib.sha256(secretKey.to_bytes(secretKey.bit_length(), 'big'))



    cipher = AES.new(key.digest(), AES.MODE_CBC, iv)

    message = b'Hi, Alice!'
    encrypted = cipher.encrypt(pad(message, AES.block_size))
    return encrypted



def decrypt(message, prkey, pukey, q, iv):
    secretKey = FastModularExponentiation(pukey, prkey, q)
    key = hashlib.sha256(secretKey.to_bytes(secretKey.bit_length(), 'big'))

    cipher = AES.new(key.digest(), AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(message), AES.block_size)
    return decrypted




def genkeys(alpha, q):
    prkey = genPrivateKey(q)
    pukey = FastModularExponentiation(alpha, prkey, q)
    return (prkey, pukey)

def task1():
    alpha = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
    q = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
    iv = get_random_bytes(16)

    aliceprkey, alicepukey = genkeys(alpha, q)
    bobsprkey, bobspukey = genkeys(alpha, q)


    alicesmessage = alice(bobspukey, aliceprkey, q, iv)
    bobsmessage = bob(alicepukey, bobsprkey, q, iv)



    print(bobDecrypt(alicesmessage, bobsprkey, alicepukey, q, iv))
    print(aliceDecrypt(bobsmessage, aliceprkey, bobspukey, q, iv))




def task2a():
    alpha = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
    q = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
    iv = get_random_bytes(16)

    aliceprkey, alicepukey = genkeys(alpha, q)
    bobsprkey, bobspukey = genkeys(alpha, q)

    bobspukey = q
    alicepukey = q

    alicesmessage = alice(bobspukey, aliceprkey, q, iv)
    bobsmessage = bob(alicepukey, bobsprkey, q, iv)

    print(decrypt(alicesmessage, bobsprkey, alicepukey, q, iv))
    print(decrypt(bobsmessage, aliceprkey, bobspukey, q, iv))



def task2b():
    alpha = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371

    q = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5

    alpha = q

    iv = get_random_bytes(16)

    aliceprkey, alicepukey = genkeys(alpha, q)
    bobsprkey, bobspukey = genkeys(alpha, q)



    alicesmessage = alice(bobspukey, aliceprkey, q, iv)
    bobsmessage = bob(alicepukey, bobsprkey, q, iv)

    malloryprkey, mallorypukey = genkeys(q, q)
    bobdecrypted = decrypt(bobsmessage, malloryprkey, bobspukey, q, iv)
    alicedecrypted = decrypt(alicesmessage, malloryprkey, alicepukey, q, iv)
    print("Bob's message decrypted by mallory: " + bobdecrypted.decode('utf-8'))

    print("Alice's message decrypted by mallory: " + alicedecrypted.decode('utf-8'))


def moduinverse(e, Qn):
    k = 0
    while ((k*Qn + 1) % e) != 0:
        k += 1
    return int((k*Qn + 1)//int(e))

def bobscipher(pubkey):
    M = 12345678910
    return pow(M, pubkey[0], pubkey[1])


def task3a():
    bits = 2048
    p = getPrime(bits, randfunc=get_random_bytes)
    q = getPrime(bits, randfunc=get_random_bytes)
    n = p * q
    Qn = (p-1) * (q-1)

    e = 65537

    d = moduinverse(e, Qn)

    pubkey = (e, n)
    prikey = (d, n)

    M = 124889457437856876597697860578078
    print(M)
    C = pow(M, e, n)

    M2 = pow(C, d, n)
    print(M2)


def F(cipher, e):
    return cipher % (cipher-1)

def task3b():
    bits = 2048
    p = getPrime(bits, randfunc=get_random_bytes)
    q = getPrime(bits, randfunc=get_random_bytes)
    n = p * q
    Qn = (p-1) * (q-1)

    e = 65537

    d = moduinverse(e, Qn)

    alicepukey = (e, n)
    aliceprkey = (d, n)


    cipher = bobscipher(alicepukey)
    print("Cipher:", cipher)

    cipherprime = F(cipher, e)
    print("Cipher':", cipherprime)

    k = hashlib.sha256(bytes(cipherprime))

    iv = get_random_bytes(16)
    m = b"Hi, Bob!"

    c0 = AES.new(k.digest(), AES.MODE_CBC, iv).encrypt(pad(m, AES.block_size))
    print(c0)

    malloryskey = hashlib.sha256(bytes(1))
    decryptedc0 = unpad(AES.new(malloryskey.digest(), AES.MODE_CBC, iv).decrypt(c0), AES.block_size)
    print(decryptedc0)


    #signature part
    m1 = pow(1024, d, n)
    m2 = pow(4045, d, n)

    print(m1)
    print(m2)

    m3 = m1*m2
    print(m3)

    decryptm3 = pow(m3, e, n)
    print(decryptm3)

