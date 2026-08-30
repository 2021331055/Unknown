from sympy import Matrix

MOD = 26


def clean_text(text):
    return ''.join(text.split()).upper()


def encrypt(plaintext, key):
    while len(plaintext) % 3 != 0:
        plaintext += 'X'

    ciphertext = ""

    for i in range(0, len(plaintext), 3):
        block = Matrix([
            ord(plaintext[i]) - ord('A'),
            ord(plaintext[i + 1]) - ord('A'),
            ord(plaintext[i + 2]) - ord('A')
        ])

        result = key * block

        for value in result:
            value = int(value) % MOD
            ciphertext += chr(value + ord('A'))

    return ciphertext


def decrypt(ciphertext, inverse_key):
    plaintext = ""

    for i in range(0, len(ciphertext), 3):
        block = Matrix([
            ord(ciphertext[i]) - ord('A'),
            ord(ciphertext[i + 1]) - ord('A'),
            ord(ciphertext[i + 2]) - ord('A')
        ])

        result = inverse_key * block

        for value in result:
            value = int(value) % MOD
            plaintext += chr(value + ord('A'))

    return plaintext


def main():
    print("===== 3x3 HILL CIPHER =====")

    print("\nEnter the 3x3 key matrix:")

    key = []

    for i in range(3):
        row = list(map(int, input().split()))

        if len(row) != 3:
            print("Each row must contain 3 numbers.")
            return

        key.append(row)

    key = Matrix(key)

    try:
        inverse_key = key.inv_mod(26)
    except Exception:
        print("\nThis key matrix has no inverse modulo 26.")
        return

    print("\nKey Matrix:")
    print(key)

    print("\nInverse Key Matrix:")
    print(inverse_key)

    plaintext = input("\nEnter plaintext: ")

    plaintext = clean_text(plaintext)

    if not plaintext:
        print("Plaintext cannot be empty.")
        return

    ciphertext = encrypt(plaintext, key)

    print("\nPlaintext  :", plaintext)
    print("Ciphertext :", ciphertext)

    decrypted = decrypt(ciphertext, inverse_key)

    decrypted = decrypted.rstrip('X')

    print("Decrypted  :", decrypted)


main()
