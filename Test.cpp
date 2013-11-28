
#include <iostream>

#include "shared/Message.hpp"

using namespace cdax;

const std::string line = std::string(80, '#');

RSAKeyPair generateKeyPair(size_t length)
{
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(prng, length);
    RSAKeyPair keyPair(params);
    return keyPair;
}

CryptoPP::SecByteBlock generateKey(size_t length)
{
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock key(length);
    prng.GenerateBlock(key, key.size());
    return key;
}

void testEncrypt()
{
    Message *msg = new Message();
    msg->setData("foo bar");

    CryptoPP::SecByteBlock aes_key = generateKey(CryptoPP::AES::DEFAULT_KEYLENGTH);
    std::cout << "message plaintext: " << msg->getData() << std::endl;
    std::cout << "AES key: " << hex(aes_key) << std::endl;

    msg->encrypt(aes_key);
    std::cout << "AES ciphertext: " << hex(msg->getData()) << std::endl;

    msg->decrypt(aes_key);
    std::cout << "decrypted plaintext: " << msg->getData() << std::endl << line << std::endl;
}

void testHMAC()
{
    Message *msg = new Message();
    msg->setData("foo bar");

    CryptoPP::SecByteBlock hmac_key = generateKey(16);
    std::cout << "HMAC key: " << hex(hmac_key) << std::endl;

    msg->hmac(hmac_key);
    std::cout << "HMAC: " << hex(msg->getSignature()) << std::endl;

    msg->verify(hmac_key);
    std::cout << "verification successfull" << std::endl << line << std::endl;
}

void testRSA()
{
    Message *msg = new Message();
    msg->setData("foo bar");

    RSAKeyPair keypair = generateKeyPair(512);
    std::cout << "RSA public key: " << hex(keypair.getPublic()) << std::endl;
    std::cout << "RSA private key: " << hex(keypair.getPrivate()) << std::endl;

    msg->encrypt(keypair.getPublic());
    std::cout << "RSA ciphertext: " << hex(msg->getData()) << std::endl;

    msg->decrypt(keypair.getPrivate());
    std::cout << "decrypted plaintext: " << msg->getData() << std::endl << line << std::endl;

    msg->sign(keypair.getPrivate());
    std::cout << "RSA signature: " << hex(msg->getSignature()) << std::endl;

    msg->verify(keypair.getPublic());
    std::cout << "verification successfull" << std::endl << line << std::endl;
}

void testSignCrypt()
{
    Message *msg = new Message();
    msg->setData("foo bar");

    CryptoPP::SecByteBlock key = generateKey(16);
    std::cout << "AES and HMAC key: " << hex(key) << std::endl;

    msg->hmacAndEncrypt(key);
    std::cout << "HMAC: " << hex(msg->getSignature()) << std::endl;
    std::cout << "message data: " << hex(msg->getData() ) << std::endl;

    msg->decryptAndVerify(key);
    std::cout << "decrypted plaintext: " << msg->getData() << std::endl << line << std::endl;
    std::cout << "verification successfull" << std::endl << line << std::endl;
}

int main(int argc, char* argv[])
{
    std::cout << "starting tests..." << std::endl << line << std::endl;

    testEncrypt();
    testHMAC();
    testRSA();
    testSignCrypt();

    return 0;
}
