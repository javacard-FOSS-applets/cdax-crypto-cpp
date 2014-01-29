
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
RSAKeyPair* serverKeyPair;
CryptoPP::RSA::PublicKey* clientPub;
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

    // Generate RSA Parameters
    // generateRSA(serverKeyPair, clientPub, card);

    msg.sign(card);
    log("> message signed on card");

    if (msg.verify(clientPub)) {
        log("> signature verified");
    }

    msg.sign(serverKeyPair->getPrivate());
    log("> message signed");

    if (msg.verify(card)) {
        log("> signature verified on card");
    }
}

void encryptionRSATest()
{
    log("> starting tests...");

    // Generate RSA Parameters
    // generateRSA(serverKeyPair, clientPub, card);

    msg.encrypt(card);
    log("> message encrypted on card");

    if (msg.decrypt(serverKeyPair->getPrivate())) {
        log("> message decrypted");
    }

    msg.encrypt(clientPub);
    log("> message encrypted");

    if (msg.decrypt(card)) {
        log("> message decrypted on card");
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

    card->storeTopicKey(topic_key_pair.getValue());

    msg.hmac(topic_key_pair.getAuthKey());
    std::cout << "> signature: " << msg.getSignature().hex() << std::endl;

    if (msg.hmacVerify(card)) {
        log("> messaged hmac verified on card");
    }

    msg.hmac(card);
    std::cout << "> card signature: " << msg.getSignature().hex() << std::endl;

    if (msg.hmacVerify(topic_key_pair.getAuthKey())) {
        log("> messaged hmac verified");
    }
}

void testHighLevel()
{
    log("> starting tests...");

    // Generate RSA Parameters
    // generateRSA(serverKeyPair, clientPub, card);

    // test topic join response
    msg.setData(*topic_key_pair.getValue());
    msg.encrypt(clientPub);
    msg.sign(serverKeyPair->getPrivate());

    std::cout << "> topic key pair: " << topic_key_pair.getValue().hex() << std::endl;

    msg.handleTopicKeyResponse(card);
    log("> topic join response processed on card");

    // test encode and decode
    msg.setData("hello");

    msg.encode(card);
    log("> message encoded on card");
    std::cout << msg;

    msg.decode(card);
    log("> message decoded on card");
    std::cout << msg;

}

void tmp()
{
    log("> starting tests...");

    card->setDebug(true);

    card->storeTopicKey(topic_key_pair.getValue());

    bytestring data(600);
    prng.GenerateBlock(data.BytePtr(), data.size());
    msg.setData(data);

    msg.hmac(topic_key_pair.getAuthKey());

    std::cout << msg;

    card->startTimer();
    msg.hmacVerify(card);
    std::cout << "That took: " << card->getTimerMean() << std::endl;
}

/**
 * Eceute message unit tests
 * @param  argc ignored
 * @param  argv ignored
 * @return int reponse code
 */
int main(int argc, char* argv[])
{
    card->setDebug(false);
    card->connect();

    if (file_exists("data/server-priv.key") && file_exists("data/server-pub.key")) {
        CryptoPP::RSA::PublicKey* pub = RSAKeyPair::loadPubKey("data/server-pub.key");
        CryptoPP::RSA::PrivateKey* priv = RSAKeyPair::loadPrivKey("data/server-priv.key");

        serverKeyPair = new RSAKeyPair(pub, priv);
    } else {
        CryptoPP::InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(prng, 2048);
        serverKeyPair = new RSAKeyPair(params);

        RSAKeyPair::savePrivKey("data/server-priv.key", serverKeyPair->getPrivate());
        RSAKeyPair::savePubKey("data/server-pub.key", serverKeyPair->getPublic());
    }

    if (file_exists("data/client-pub.key") || false) {
        clientPub = RSAKeyPair::loadPubKey("data/client-pub.key");
    } else {
        clientPub = card->initialize(serverKeyPair->getPublic());
        RSAKeyPair::savePubKey("data/client-pub.key", clientPub);
    }

    if (clientPub == NULL) {
        log(card->getError());
    }

    // signatuteTest();
    // encryptionRSATest();
    // encryptionAESTest();
    // hmacTest();
    // testHighLevel();
    tmp();

    return 0;
}
