
#include <iostream>

#include "shared/Message.hpp"

using namespace cdax;

// ascii decoration line
const std::string line = std::string(80, '#');

/**
 * Generate a RSa key pair
 * @param  int length
 * @return RSAKeyPair
 */
RSAKeyPair generateKeyPair(size_t length)
{
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(prng, length);
    RSAKeyPair keyPair(params);
    return keyPair;
}

/**
 * Generate AES or HMAC key
 * @param  int length
 * @return CryptoPP::SecByteBlock
 */
CryptoPP::SecByteBlock generateKey(size_t length)
{
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock key(length);
    prng.GenerateBlock(key, key.size());
    return key;
}

/**
 * Test message AES CBC encryption
 */
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

/**
 * Test message HMAC
 */
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

/**
 * Test message RSA encryption and signing
 */
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

/**
 * Test message encryption and signing in one method using the same key
 */
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

/**
 * Eceute message unit tests
 * @param  argc ignored
 * @param  argv ignored
 * @return int reponse code
 */
int main(int argc, char* argv[])
{
    std::cout << "starting tests..." << std::endl << line << std::endl;

    testEncrypt();
    testHMAC();
    testRSA();
    testSignCrypt();

    return 0;
}
