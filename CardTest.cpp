
#include <string>
#include <cstdlib>
#include <iostream>

#include "card/SmartCard.hpp"
#include "shared/Message.hpp"

using namespace cdax;

// ascii decoration line
const std::string line = std::string(80, '#');

// pseudo random number generator
CryptoPP::AutoSeededRandomPool prng;
RSAKeyPair serverKeyPair;
CryptoPP::RSA::PublicKey clientPub;
SmartCard *card = new SmartCard();

// create message
Message msg("test_id", "test_topic", "test_data");

void log(std::string msg)
{
    std::cout << msg << std::endl << line << std::endl;
}

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

TopicKeyPair topic_key_pair(
    generateKey(TopicKeyPair::KeyLength),
    generateKey(TopicKeyPair::KeyLength)
);

void signatuteTest()
{
    log("> starting tests...");

    msg.sign(card);
    log("> message signed on card");

    if (msg.verify(clientPub)) {
        log("> signature verified");
    } else {
        log("> ERROR");
    }

    msg.sign(serverKeyPair.getPrivate());
    log("> message signed");

    if (msg.verify(card)) {
        log("> signature verified on card");
    } else {
        log("> ERROR");
    }
}

void encryptionRSATest()
{
    log("> starting tests...");

    msg.encrypt(card);
    log("> message encrypted on card");

    if (msg.decrypt(serverKeyPair.getPrivate())) {
        log("> message decrypted");
    } else {
        log("> ERROR");
    }

    msg.encrypt(clientPub);
    log("> message encrypted");

    if (msg.decrypt(card)) {
        log("> message decrypted on card");
    } else {
        log("> ERROR");
    }
}

void encryptionAESTest()
{
    log("> starting tests...");

    std::cout << "> key: " << topic_key_pair.getEncKey().hex() << std::endl;

    card->storeTopicKey(topic_key_pair.getValue());

    log("> stored key on card");

    msg.aesEncrypt(topic_key_pair.getEncKey());
    log("> message encrypted");

    msg.aesDecrypt(card);
    log("> message decrypted on card");

    msg.aesEncrypt(card);
    log("> message encrypted on card");

    msg.aesDecrypt(topic_key_pair.getEncKey());
    log("> message decrypted");

}

void hmacTest()
{
    log("> starting tests...");

    size_t key_index = 250;

    card->storeTopicKey(topic_key_pair.getValue(), key_index);

    msg.hmac(topic_key_pair.getAuthKey());
    std::cout << "> signature: " << msg.getSignature().hex() << std::endl;

    if (msg.hmacVerify(card, key_index)) {
        log("> messaged hmac verified on card");
    } else {
        log("> ERROR");
    }

    msg.hmac(card, key_index);
    std::cout << "> card signature: " << msg.getSignature().hex() << std::endl;

    if (msg.hmacVerify(topic_key_pair.getAuthKey())) {
        log("> messaged hmac verified");
    } else {
        log("> ERROR");
    }
}

void testHighLevel()
{
    log("> starting tests...");

    card->setDebug(true);

    // test topic join response
    msg.setData(topic_key_pair.getValue());
    msg.encrypt(clientPub);
    msg.sign(serverKeyPair.getPrivate());

    std::cout << "> topic key pair 0: " << topic_key_pair.getValue().hex() << std::endl;

    msg.handleTopicKeyResponse(card);
    log("> topic join response processed on card with key 0");

    // test encode and decode
    msg.setData("hello");

    msg.encode(card);
    log("> message encoded on card with key 0");
    std::cout << msg;

    msg.decode(card);
    log("> message decoded on card with key 0");
    std::cout << msg;

    TopicKeyPair topic_key_pair2(
        generateKey(TopicKeyPair::KeyLength),
        generateKey(TopicKeyPair::KeyLength)
    );


    // test topic join response
    msg.setData(topic_key_pair.getValue());
    msg.encrypt(clientPub);
    msg.sign(serverKeyPair.getPrivate());

    std::cout << "> topic key pair 1: " << topic_key_pair.getValue().hex() << std::endl;

    msg.handleTopicKeyResponse(card, 1);
    log("> topic join response processed on card with key 1");

    // test encode and decode
    msg.setData("hello");

    msg.encode(card, 1);
    log("> message encoded on card with key 1");
    std::cout << msg;

    msg.decode(card, 1);
    log("> message decoded on card with key 1");
    std::cout << msg;
}

void testMaxSize()
{
    log("> starting tests...");

    card->setDebug(true);

    int len = 1456;
    byte p1, p2;
    bytestring data;

    data.resize(len);
    std::fill(data.BytePtr(), data.BytePtr() + data.size(), 42);

    p1 = (len >> 8) & 0xff;
    p2 = len & 0xff;
    card->transmit(0x04, data, p1, p2);
}

/**
 * Eceute message unit tests
 * @param  argc ignored
 * @param  argv ignored
 * @return int reponse code
 */
int main(int argc, char* argv[])
{
    card->setDebug(true);
    card->connect();

    // if (file_exists("data/server-priv.key") && file_exists("data/server-pub.key")) {
    //     CryptoPP::RSA::PublicKey pub = RSAKeyPair::loadPubKey("data/server-pub.key");
    //     CryptoPP::RSA::PrivateKey priv = RSAKeyPair::loadPrivKey("data/server-priv.key");

    //     serverKeyPair = RSAKeyPair(pub, priv);
    // } else {
    //     CryptoPP::InvertibleRSAFunction params;
    //     params.GenerateRandomWithKeySize(prng, 2048);
    //     serverKeyPair = RSAKeyPair(params);

    //     RSAKeyPair::saveKey("data/server-priv.key", serverKeyPair.getPrivate());
    //     RSAKeyPair::saveKey("data/server-pub.key", serverKeyPair.getPublic());
    // }

    // if (file_exists("data/client-pub.key")) {
    //     clientPub = RSAKeyPair::loadPubKey("data/client-pub.key");
    // } else {
    //     clientPub = card->initialize(serverKeyPair.getPublic());
    //     RSAKeyPair::saveKey("data/client-pub.key", clientPub);
    // }

    // signatuteTest();
    // encryptionRSATest();
    // encryptionAESTest();
    // hmacTest();
    // testHighLevel();
    testMaxSize();

    return 0;
}
