
#include <iostream>

#include "Message.hpp"

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

void testAES_CBC()
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

void testAES_GCM()
{
    Message *msg = new Message();
    msg->setData("foo bar");

    CryptoPP::SecByteBlock aes_key = generateKey(CryptoPP::AES::DEFAULT_KEYLENGTH);
    std::cout << "AES GCM key: " << hex(aes_key) << std::endl;

    msg->setCipher(Cipher::AES_GCM);
    msg->encrypt(aes_key);
    std::cout << "AES GCM ciphertext: " << hex(msg->getData()) << std::endl;

    msg->decrypt(aes_key);
    std::cout << "decrypted plaintext: " << msg->getData() << std::endl;
    std::cout << "verification successfull" << std::endl << line << std::endl;
}

void testSalsa()
{
    Message *msg = new Message();
    msg->setData("foo bar");

    CryptoPP::SecByteBlock salsa_key = generateKey(CryptoPP::Salsa20::DEFAULT_KEYLENGTH);
    std::cout << "Salsa key: " << hex(salsa_key) << std::endl;

    msg->setCipher(Cipher::Salsa20);
    msg->encrypt(salsa_key);
    std::cout << "Salsa ciphertext: " << hex(msg->getData()) << std::endl;

    msg->decrypt(salsa_key);
    std::cout << "decrypted plaintext: " << msg->getData() << std::endl << line << std::endl;
}

void testHMAC()
{
    Message *msg = new Message();
    msg->setData("foo bar");

    CryptoPP::SecByteBlock hmac_key = generateKey(16);
    std::cout << "HMAC key: " << hex(hmac_key) << std::endl;

    msg->sign(hmac_key);
    std::cout << "HMAC: " << hex(msg->getSignature()) << std::endl;

    msg->verify(hmac_key);
    std::cout << "verification successfull" << std::endl << line << std::endl;
}

void testRSA()
{
    Message *msg = new Message();
    msg->setData("foo bar");

    RSAKeyPair keypair = generateKeyPair(512);
    // std::cout << "RSA public key: " << hex(keypair.getPublic()) << std::endl;
    // std::cout << "RSA private key: " << hex(keypair.getPrivate()) << std::endl;

    msg->encrypt(keypair.getPublic());
    std::cout << "RSA ciphertext: " << hex(msg->getData()) << std::endl;

    msg->decrypt(keypair.getPrivate());
    std::cout << "decrypted plaintext: " << msg->getData() << std::endl << line << std::endl;

    msg->sign(keypair.getPrivate());
    std::cout << "RSA signature: " << hex(msg->getSignature()) << std::endl;

    msg->verify(keypair.getPublic());
    std::cout << "verification successfull" << std::endl << line << std::endl;
}

void testTopicKeyPair()
{
    TopicKeyPair kp1 = TopicKeyPair(generateKey(16), generateKey(16));
    std::cout << hex(kp1.getEncKey()) << " - " << hex(kp1.getAuthKey()) << std::endl;
    std::string archive = kp1.toString();
    std::cout << archive << std::endl;
    TopicKeyPair kp2 = TopicKeyPair(archive);
    std::cout << hex(kp2.getEncKey()) << " - " << hex(kp2.getAuthKey()) << std::endl;
}

int main(int argc, char* argv[])
{
    std::cout << "starting tests..." << std::endl << line << std::endl;

    testAES_CBC();
    testSalsa();
    testAES_GCM();
    testHMAC();
    testRSA();
    // testTopicKeyPair();

    return 0;
}
