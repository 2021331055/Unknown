#include <bits/stdc++.h>

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/pssr.h>

using namespace std;
using namespace CryptoPP;

AutoSeededRandomPool prng;

// ---------------- Save Keys ----------------
void SaveKeyToFile(const string &filename, const SecByteBlock &key)
{
    FileSink file(filename.c_str());
    file.Put(key, key.size());
}

void SaveRSAPrivateKey(const string &filename, const RSA::PrivateKey &key)
{
    FileSink file(filename.c_str());
    key.DEREncodePrivateKey(file);
}

void SaveRSAPublicKey(const string &filename, const RSA::PublicKey &key)
{
    FileSink file(filename.c_str());
    key.DEREncode(file);
}

// ----------------------------------------------
// 1. AES ENCRYPTION & DECRYPTION
// ----------------------------------------------
void doAES()
{
    int keyChoice, modeChoice;

    cout << "Choose Key Size (128/192/256): ";
    cin >> keyChoice;

    cout << "Choose Mode (1=ECB, 2=CFB): ";
    cin >> modeChoice;

    int byteSize;

    if (keyChoice == 128)
        byteSize = 16;
    else if (keyChoice == 192)
        byteSize = 24;
    else
        byteSize = 32;

    SecByteBlock key(byteSize);
    SecByteBlock iv(AES::BLOCKSIZE);

    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    SaveKeyToFile("aes_key.bin", key);
    SaveKeyToFile("aes_iv.bin", iv);

    ofstream("input.txt") << "This is a secret message for AES testing.";

    clock_t start = clock();

    if (modeChoice == 1)
    {
        ECB_Mode<AES>::Encryption enc;
        enc.SetKey(key, key.size());

        FileSource("input.txt", true,
                   new StreamTransformationFilter(enc,
                                                  new FileSink("aes_encrypted.bin")));
    }
    else
    {
        CFB_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), iv);

        FileSource("input.txt", true,
                   new StreamTransformationFilter(enc,
                                                  new FileSink("aes_encrypted.bin")));
    }

    clock_t end = clock();

    cout << "AES Encryption Time: "
         << double(end - start) / CLOCKS_PER_SEC
         << " seconds\n";

    string recovered;

    if (modeChoice == 1)
    {
        ECB_Mode<AES>::Decryption dec;
        dec.SetKey(key, key.size());

        FileSource("aes_encrypted.bin", true,
                   new StreamTransformationFilter(dec,
                                                  new StringSink(recovered)));
    }
    else
    {
        CFB_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv);

        FileSource("aes_encrypted.bin", true,
                   new StreamTransformationFilter(dec,
                                                  new StringSink(recovered)));
    }

    cout << "Decrypted Text: " << recovered << "\n\n";
}

// ----------------------------------------------
// 2. RSA ENCRYPTION & DECRYPTION
// ----------------------------------------------
void doRSA()
{
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(prng, 2048);

    RSA::PublicKey publicKey(privateKey);

    SaveRSAPrivateKey("rsa_private.key", privateKey);
    SaveRSAPublicKey("rsa_public.key", publicKey);

    ofstream("input.txt") << "RSA Secret Data";

    clock_t start = clock();

    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

    FileSource("input.txt", true,
               new PK_EncryptorFilter(prng,
                                      encryptor,
                                      new FileSink("rsa_encrypted.bin")));

    clock_t end = clock();

    cout << "RSA Encryption Time: "
         << double(end - start) / CLOCKS_PER_SEC
         << " seconds\n";

    string recovered;

    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

    FileSource("rsa_encrypted.bin", true,
               new PK_DecryptorFilter(prng,
                                      decryptor,
                                      new StringSink(recovered)));

    cout << "RSA Decrypted Text: " << recovered << "\n\n";
}

// ----------------------------------------------
// 3. RSA DIGITAL SIGNATURE
// ----------------------------------------------
void doRSASig()
{
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(prng, 2048);

    RSA::PublicKey publicKey(privateKey);

    ofstream("input.txt") << "Document to be signed.";

    RSASS<PKCS1v15, SHA256>::Signer signer(privateKey);

    FileSource("input.txt", true,
               new SignerFilter(prng,
                                signer,
                                new FileSink("signature.bin")));

    cout << "Signature created.\n";

    string message;
    string signature;

    FileSource("input.txt", true,
               new StringSink(message));

    FileSource("signature.bin", true,
               new StringSink(signature));

    RSASS<PKCS1v15, SHA256>::Verifier verifier(publicKey);

    bool valid = verifier.VerifyMessage(
        reinterpret_cast<const CryptoPP::byte *>(message.data()),
        message.size(),
        reinterpret_cast<const CryptoPP::byte *>(signature.data()),
        signature.size());

    if (valid)
        cout << "Result: Signature is VALID.\n\n";
    else
        cout << "Result: Signature is INVALID.\n\n";
}

// ----------------------------------------------
// 4. SHA-256 HASHING
// ----------------------------------------------
void doSHA256()
{
    ofstream("input.txt") << "Hash this text.";

    string digest;

    SHA256 hash;

    FileSource("input.txt", true,
               new HashFilter(hash,
                              new HexEncoder(new StringSink(digest))));

    cout << "SHA-256 Hash:\n"
         << digest << "\n\n";
}

// ----------------------------------------------
// 5. BENCHMARK
// ----------------------------------------------
void doBenchmark()
{
    cout << "--- AES Benchmark ---\n";

    int aesSizes[] = {16, 24, 32};

    for (int size : aesSizes)
    {
        SecByteBlock key(size);
        prng.GenerateBlock(key, size);

        ECB_Mode<AES>::Encryption enc;
        enc.SetKey(key, size);

        string out;

        clock_t start = clock();

        StringSource("Testing time", true,
                     new StreamTransformationFilter(enc,
                                                    new StringSink(out)));

        clock_t end = clock();

        cout << "AES " << size * 8
             << "-bit: "
             << double(end - start) / CLOCKS_PER_SEC
             << " sec\n";
    }

    cout << "\n--- RSA Key Generation Benchmark ---\n";

    int rsaSizes[] = {1024, 1536, 2048, 3072, 4096};

    for (int size : rsaSizes)
    {
        clock_t start = clock();

        RSA::PrivateKey key;
        key.GenerateRandomWithKeySize(prng, size);

        clock_t end = clock();

        cout << "RSA " << size
             << "-bit: "
             << double(end - start) / CLOCKS_PER_SEC
             << " sec\n";
    }

    cout << "\n";
}

// ----------------------------------------------
// MAIN
// ----------------------------------------------
int main()
{
    while (true)
    {
        int choice;

        cout << "===== CRYPTO LAB MENU =====\n";
        cout << "1. AES Encryption/Decryption\n";
        cout << "2. RSA Encryption/Decryption\n";
        cout << "3. RSA Digital Signature\n";
        cout << "4. SHA-256 Hashing\n";
        cout << "5. Benchmark\n";
        cout << "6. Exit\n";
        cout << "Choice: ";

        cin >> choice;

        switch (choice)
        {
        case 1:
            doAES();
            break;
        case 2:
            doRSA();
            break;
        case 3:
            doRSASig();
            break;
        case 4:
            doSHA256();
            break;
        case 5:
            doBenchmark();
            break;
        case 6:
            return 0;
        default:
            cout << "Invalid Choice.\n";
        }
    }
}