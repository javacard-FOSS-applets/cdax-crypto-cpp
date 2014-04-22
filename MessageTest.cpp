
#include <iostream>

#include "shared/Message.hpp"

using namespace cdax;

// ascii decoration line
const std::string line = std::string(80, '#');

/**
 * Generate AES or HMAC key
 * @param  int length
 * @return bytestring
 */
bytestring generateKey(size_t length)
{
    CryptoPP::AutoSeededRandomPool prng;
    bytestring key(length);
    prng.GenerateBlock(key.BytePtr(), key.size());
    return key;
}

/**
 * Test message AES CBC encryption
 */
void testEncrypt()
{
    Message *msg = new Message();
    msg->setData("foo bar");

    bytestring aes_key = generateKey(CryptoPP::AES::DEFAULT_KEYLENGTH);
    std::cout << "message plaintext: " << msg->getData().str() << std::endl;
    std::cout << "message plaintext: " << msg->getData().hex() << std::endl;
    std::cout << "AES key: " << aes_key.hex() << std::endl;

    msg->aesEncrypt(aes_key);
    std::cout << "AES ciphertext: " << msg->getData().hex() << std::endl;

    msg->aesDecrypt(aes_key);
    std::cout << "decrypted plaintext: " << msg->getData().str() << std::endl << line << std::endl;
}

/**
 * Test message HMAC
 */
void testHMAC()
{
    Message *msg = new Message();
    msg->setData("foo bar");

    bytestring hmac_key = generateKey(16);
    std::cout << "HMAC key: " << hmac_key.hex() << std::endl;

    msg->hmac(hmac_key);
    std::cout << "HMAC: " << msg->getSignature().hex() << std::endl;

    msg->hmacVerify(hmac_key);
    std::cout << "verification successfull" << std::endl << line << std::endl;
}

/**
 * Test message RSA encryption and signing
 */
void testRSA()
{
    Message *msg = new Message();
    msg->setData("foo bar");

    std::cout << "RSA plaintext: " << msg->getData().hex() << std::endl;

    RSAKeyPair* keypair = new RSAKeyPair(2048);

    msg->encrypt(keypair->getPublic());
    std::cout << "RSA ciphertext: " << msg->getData().hex() << std::endl;

    msg->decrypt(keypair->getPrivate());
    std::cout << "decrypted plaintext: " << msg->getData().hex() << std::endl << line << std::endl;

    msg->sign(keypair->getPrivate());
    std::cout << "RSA signature: " << msg->getSignature().hex() << std::endl;

    msg->verify(keypair->getPublic());
    std::cout << "verification successfull" << std::endl << line << std::endl;
}

void testEncode()
{
    Message msg = Message("foo", "bar", "baz");

    RSAKeyPair* keypair = new RSAKeyPair(2048);
    bytestring key = generateKey(16);

    msg.encrypt(keypair->getPublic());
    msg.sign(keypair->getPrivate());
    msg.aesEncrypt(key);

    std::cout << "Message:" << msg << std::endl;

    bytestring encoded = (bytestring) msg.encode();

    std::cout << "Encoded:" << encoded.hex() << std::endl;

    Message msg2 = Message();
    msg2.decode(encoded.str());

    std::cout << "Decoded:" << msg2 << std::endl;
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
    testEncode();

    return 0;
}
