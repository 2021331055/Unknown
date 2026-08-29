from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


import os
import time

# FILE FUNCTIONS

def save_file(filename, data):
    with open(filename, "wb") as f:
        f.write(data)
        
def read_file(filename):
    with open(filename, "rb") as f:
        return f.read()

# KEY GENERATION

def generate_keys():
    # AES-128 key
    if not os.path.exists("aes128.key"):
        key128 = get_random_bytes(16)
        save_file("aes128.key", key128)
        print("AES-128 key generated.")

    # AES-256 key
    if not os.path.exists("aes256.key"):
        key256 = get_random_bytes(32)
        save_file("aes256.key", key256)
        print("AES-256 key generated.")
        
    # RSA keys
    if not os.path.exists("rsa_private.pem"):
        print("Generating RSA 2048-bit keys...")
        private_key = RSA.generate(2048)
        public_key = private_key.publickey()
        save_file(
            "rsa_private.pem",
            private_key.export_key()
        )
        save_file(
            "rsa_public.pem",
            public_key.export_key()
        )
        print("RSA keys generated.")

# CREATE INPUT FILE

def create_input_file():
    if not os.path.exists("input.txt"):
        text = (
            "This is a secret message for "
            "CSE-478 Introduction to Computer Security Lab 4."
        )
        with open("input.txt", "w") as f:
            f.write(text)

# AES ENCRYPTION

def aes_encrypt(key_size, mode):
    if key_size == 128:
        key = read_file("aes128.key")
    else:
        key = read_file("aes256.key")
    data = read_file("input.txt")
    start = time.perf_counter()

    # ECB MODE
    
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        # ECB requires padding
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        # No IV required for ECB
        save_file(
            "aes_encrypted.bin",
            encrypted_data
        )
 
    # CFB MODE
   
    elif mode == "CFB":
        # Generate random IV
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(
            key,
            AES.MODE_CFB,
            iv=iv
        )
        encrypted_data = cipher.encrypt(data)
        # Save IV + ciphertext
        save_file(
            "aes_encrypted.bin",
            iv + encrypted_data
        )
    end = time.perf_counter()
    elapsed = (end - start) * 1000

    print("\nAES Encryption Completed")
    print("Key Size :", key_size, "bits")
    print("Mode     :", mode)
    print("Output   : aes_encrypted.bin")
    print("Time     :", round(elapsed, 6), "ms")

# AES DECRYPTION

def aes_decrypt(key_size, mode):
    if key_size == 128:
        key = read_file("aes128.key")
    else:
        key = read_file("aes256.key")
    encrypted_data = read_file(
        "aes_encrypted.bin"
    )
    start = time.perf_counter()
    
    # ECB DECRYPTION
   
    if mode == "ECB":
        cipher = AES.new(
            key,
            AES.MODE_ECB
        )
        decrypted_data = cipher.decrypt(
            encrypted_data
        )
        # Remove padding
        decrypted_data = unpad(
            decrypted_data,
            AES.block_size
        )

    # CFB DECRYPTION

    elif mode == "CFB":
        # First 16 bytes are IV
        iv = encrypted_data[:AES.block_size]
        ciphertext = encrypted_data[
            AES.block_size:
        ]
        cipher = AES.new(
            key,
            AES.MODE_CFB,
            iv=iv
        )
        decrypted_data = cipher.decrypt(
            ciphertext
        )
    end = time.perf_counter()
    elapsed = (end - start) * 1000

    print("\nAES Decryption Completed")
    print("Key Size :", key_size, "bits")
    print("Mode     :", mode)
    print("\nDecrypted Text:")
    print(decrypted_data.decode())
    print("\nTime :", round(elapsed, 6), "ms")

# RSA ENCRYPTION

def rsa_encrypt():
    public_key = RSA.import_key(
        read_file("rsa_public.pem")
    )
    data = read_file("input.txt")
    cipher = PKCS1_OAEP.new(
        public_key,
        hashAlgo=SHA256
    )
    start = time.perf_counter()
    encrypted_data = cipher.encrypt(data)
    end = time.perf_counter()
    save_file(
        "rsa_encrypted.bin",
        encrypted_data
    )
    elapsed = (end - start) * 1000

    print("\nRSA Encryption Completed")
    print("Key Size : 2048 bits")
    print("Output   : rsa_encrypted.bin")
    print("Time     :", round(elapsed, 6), "ms")

# RSA DECRYPTION

def rsa_decrypt():
    private_key = RSA.import_key(
        read_file("rsa_private.pem")
    )
    encrypted_data = read_file(
        "rsa_encrypted.bin"
    )
    cipher = PKCS1_OAEP.new(
        private_key,
        hashAlgo=SHA256
    )
    start = time.perf_counter()
    decrypted_data = cipher.decrypt(
        encrypted_data
    )
    end = time.perf_counter()
    elapsed = (end - start) * 1000

    print("\nRSA Decryption Completed")
    print("\nDecrypted Text:")
    print(decrypted_data.decode())
    print("\nTime :", round(elapsed, 6), "ms")

# RSA SIGNATURE

def rsa_sign():
    private_key = RSA.import_key(
        read_file("rsa_private.pem")
    )
    data = read_file("input.txt")
    # SHA-256 hash
    message_hash = SHA256.new(data)
    signer = pss.new(private_key)
    start = time.perf_counter()
    signature = signer.sign(message_hash)
    end = time.perf_counter()
    save_file(
        "signature.bin",
        signature
    )
    elapsed = (end - start) * 1000

    print("\nRSA Signature Created")
    print("Output :", "signature.bin")
    print("Time   :", round(elapsed, 6), "ms")

# RSA SIGNATURE VERIFICATION

def rsa_verify():
    public_key = RSA.import_key(
        read_file("rsa_public.pem")
    )
    data = read_file("input.txt")
    signature = read_file(
        "signature.bin"
    )
    message_hash = SHA256.new(data)
    verifier = pss.new(public_key)
    start = time.perf_counter()
    try:
        verifier.verify(
            message_hash,
            signature
        )
        result = True
    except (ValueError, TypeError):
        result = False
    end = time.perf_counter()
    elapsed = (end - start) * 1000
    print("\nRSA Signature Verification")
    if result:
        print("Result : VALID")
    else:
        print("Result : INVALID")
    print("Time   :", round(elapsed, 6), "ms")

# SHA-256 HASH

def sha256_hash():
    data = read_file("input.txt")
    start = time.perf_counter()
    hash_value = SHA256.new(data)
    end = time.perf_counter()
    elapsed = (end - start) * 1000
    print("\nSHA-256 Hash:")
    print(hash_value.hexdigest())
    print("\nTime :", round(elapsed, 6), "ms")


# AES BENCHMARK

def aes_benchmark():
    print("\n====================================")
    print("AES EXECUTION TIME")
    print("====================================")
    # AES does NOT support 16-bit keys.
    # Valid AES key sizes are 128, 192 and 256 bits.
    key_sizes = [128, 192, 256]
    data = b"This is benchmark data."
    for size in key_sizes:
        key = get_random_bytes(size // 8)
        cipher = AES.new(
            key,
            AES.MODE_ECB
        )
        padded_data = pad(
            data,
            AES.block_size
        )
        start = time.perf_counter()
        cipher.encrypt(padded_data)
        end = time.perf_counter()
        elapsed = (end - start) * 1000
        print(
            f"AES-{size} : "
            f"{elapsed:.6f} ms"
        )

# RSA BENCHMARK

def rsa_benchmark():
    print("\n====================================")
    print("RSA KEY SIZE BENCHMARK")
    print("====================================")
    key_sizes = [
        1024,
        1536,
        2048,
        3072,
        4096
    ]
    for size in key_sizes:
        start = time.perf_counter()
        RSA.generate(size)
        end = time.perf_counter()
        elapsed = (end - start) * 1000
        print(
            f"RSA-{size} : "
            f"{elapsed:.6f} ms"
        )

# COMPLETE BENCHMARK

def benchmark():
    aes_benchmark()
    rsa_benchmark()
    print()
    

# MENU

def menu():
    while True:

        print("\n")
        print("======================================")
        print("       CSE-478 CRYPTO LAB 4")
        print("======================================")

        print("1. AES-128 ECB Encryption/Decryption")
        print("2. AES-128 CFB Encryption/Decryption")
        print("3. AES-256 ECB Encryption/Decryption")
        print("4. AES-256 CFB Encryption/Decryption")
        print("5. RSA Encryption/Decryption")
        print("6. RSA Signature & Verification")
        print("7. SHA-256 Hash")
        print("8. Benchmark Execution Time")
        print("0. Exit")
        print("======================================")
        choice = input(
            "Enter your choice: "
        )
        # AES-128 ECB
        if choice == "1":
            aes_encrypt(
                128,
                "ECB"
            )
            aes_decrypt(
                128,
                "ECB"
            )
        # AES-128 CFB
        elif choice == "2":
            aes_encrypt(
                128,
                "CFB"
            )
            aes_decrypt(
                128,
                "CFB"
            )
        # AES-256 ECB
        elif choice == "3":
            aes_encrypt(
                256,
                "ECB"
            )
            aes_decrypt(
                256,
                "ECB"
            )
        # AES-256 CFB
        elif choice == "4":
            aes_encrypt(
                256,
                "CFB"
            )
            aes_decrypt(
                256,
                "CFB"
            )
        # RSA
        elif choice == "5":
            rsa_encrypt()
            rsa_decrypt()
        # RSA Signature
        elif choice == "6":
            rsa_sign()
            rsa_verify()
        # SHA256
        elif choice == "7":
            sha256_hash()
        # Benchmark
        elif choice == "8":
            benchmark()
        # Exit
        elif choice == "0":
            print("\nProgram terminated.")
            break
        else:
            print("\nInvalid choice!")

# PROGRAM START

if __name__ == "__main__":
    
    print("Initializing Crypto Lab...")
    generate_keys()
    create_input_file()
    print("Initialization completed.")
    menu()
