''' encoding: Unicode (UTF-8) utf-8 '''

import os
import argparse
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as padding2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key





def generate_hybrid_system_keys(symmetric_key_txt, public_key_pem, secret_key_pem, N):
    
    # генерация ключа для симметричного алгоритма
    symmetric_key = os.urandom(N)
    
    # генерация ключей для асимметричного алгоритма
    keys = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)
    secret_key = keys
    public_key = keys.public_key()
    
    # сериализация асимметричных ключей
    with open(public_key_pem, 'wb') as file:
            file.write(public_key.public_bytes(encoding = serialization.Encoding.PEM, 
                                               format = serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(secret_key_pem, 'wb') as file:
            file.write(secret_key.private_bytes(encoding = serialization.Encoding.PEM, 
                                                format = serialization.PrivateFormat.TraditionalOpenSSL, 
                                                encryption_algorithm = serialization.NoEncryption()))
    
    # шифрование симметричного ключа открытым ключом при помощи RSA-OAEP и сохранение его в файл
    with open(symmetric_key_txt, 'wb') as file:
        file.write(public_key.encrypt(symmetric_key, padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()), 
                                                                  algorithm = hashes.SHA256(), label = None)))


def encrypt_hybrid_system_data(initial_file_txt, secret_key_pem, symmetric_key_txt, encrypted_file_txt, iv_txt):
    
    # дешифрование симметричного ключа
    with open(secret_key_pem, 'rb') as file:
        secret_key = load_pem_private_key(file.read(), password = None)
    with open(symmetric_key_txt, 'rb') as file:
        symmetric_key = secret_key.decrypt(file.read(), padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()), 
                                                                     algorithm = hashes.SHA256(), label = None))
    
    # шифрование текста симметричным алгоритмом и сохранение его в файл
    padder = padding2.ANSIX923(64).padder()
    with open(initial_file_txt, 'rb') as file:
        padded_initial_file = padder.update(file.read()) + padder.finalize()
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    with open(encrypted_file_txt, 'wb') as file:
        file.write(encryptor.update(padded_initial_file) + encryptor.finalize())
    with open(iv_txt, 'wb') as file:
        file.write(iv)


def decrypt_hybrid_system_data(encrypted_file_txt, secret_key_pem, symmetric_key_txt, decrypted_file_txt, iv_txt):
    
    # дешифрование симметричного ключа
    with open(secret_key_pem, 'rb') as file:
        secret_key = load_pem_private_key(file.read(), password = None)
    with open(symmetric_key_txt, 'rb') as file:
        symmetric_key = secret_key.decrypt(file.read(), padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()), 
                                                                     algorithm = hashes.SHA256(), label = None))
    
    # дешифрование текста симметричным алгоритмом и сохранение его в файл
    with open(iv_txt, 'rb') as file:
        iv = file.read()
    cipher = Cipher(algorithms.TripleDES(symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    with open(encrypted_file_txt, 'rb') as file:
        decrypted_file = decryptor.update(file.read()) + decryptor.finalize()
    unpadder = padding2.ANSIX923(64).unpadder()
    with open(decrypted_file_txt, 'wb') as file:
        file.write(unpadder.update(decrypted_file) + unpadder.finalize())



parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required = True)
group.add_argument('-gen', '--generation', action = 'store_const', const = 'generation_mode', help = 'Starts generation mode')
group.add_argument('-enc', '--encryption', action = 'store_const', const = 'encryption_mode', help = 'Starts encryption mode')
group.add_argument('-dec', '--decryption', action = 'store_const', const = 'decryption_mode', help = 'Starts decryption mode')
parser.add_argument('way', type = str, help = 'Way to the folder with the initial_file.txt')
parser.add_argument('n', type = int, help = 'Encryption key length (8, 16 or 24 bytes)')
args = parser.parse_args()


if args.n not in set([8, 16, 24]):
    print('Invalid encryption key length')
else:
    initial_file_txt = args.way + '\\initial_file.txt'
    encrypted_file_txt = args.way + '\\encrypted_file.txt'
    decrypted_file_txt = args.way + '\\decrypted_file.txt'
    symmetric_key_txt = args.way + '\\symmetric_key.txt'
    public_key_pem = args.way + '\\public_key.pem'
    secret_key_pem = args.way + '\\secret_key.pem'
    iv_txt = args.way + '\\iv.txt'
    
    if args.generation is not None:
        generate_hybrid_system_keys(symmetric_key_txt, public_key_pem, secret_key_pem, args.n)
        print('Generation completed')
    elif args.encryption is not None:
        if not os.path.exists(secret_key_pem):
            print('File secret_key.pem doesn\'t exist')
        elif not os.path.exists(symmetric_key_txt):
            print('File symmetric_key.txt doesn\'t exist')
        elif not os.path.exists(initial_file_txt):
            print('File initial_file.txt doesn\'t exist')
        else:
            encrypt_hybrid_system_data(initial_file_txt, secret_key_pem, symmetric_key_txt, encrypted_file_txt, iv_txt)
            print('Encryption completed')
    else:
        if not os.path.exists(secret_key_pem):
            print('File secret_key.pem doesn\'t exist')
        elif not os.path.exists(symmetric_key_txt):
            print('File symmetric_key.txt doesn\'t exist')
        elif not os.path.exists(iv_txt):
            print('File iv.txt doesn\'t exist')
        elif not os.path.exists(encrypted_file_txt):
            print('File encrypted_file.txt doesn\'t exist')
        else:
            decrypt_hybrid_system_data(encrypted_file_txt, secret_key_pem, symmetric_key_txt, decrypted_file_txt, iv_txt)
            print('Decryption completed')
