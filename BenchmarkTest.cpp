
#include <string>
#include <cstdlib>
#include <iostream>
#include <unistd.h>

#include "card/SmartCard.hpp"
#include "shared/Message.hpp"

using namespace cdax;

CryptoPP::AutoSeededRandomPool prng;

bytestring generateKey(size_t length)
{
    CryptoPP::AutoSeededRandomPool prng;
    bytestring key(length);
    prng.GenerateBlock(key.BytePtr(), key.size());
    return key;
}


void throughputBenchmark()
{
    std::cout << "> starting tests..." << std::endl;

    SmartCard *card = new SmartCard();

    card->setDebug(false);

    if (card == NULL) {
        return;
    }

    if (!card->connect()) {
        return;
    }

    bytestring data;
    int len, repeat = 10, max = 25;
    byte p1, p2;

    std::cout << "Sending:" << std::endl;

    for (int i = 0; i <= max; i++) {
        len = 50 * i;
        card->startTimer();
        for (int j = 0; j <= repeat; j++) {
            data.resize(len);
            card->transmit(0x05, data);
        }
        std::cout << "(" << len << ", " << card->stopTimer() << ")" << std::endl;
    }

    std::cout << "Receiving:" << std::endl;

    for (int i = 0; i <= max; i++) {
        len = 50 * i;
        card->startTimer();
        for (int j = 0; j <= repeat; j++) {
            data.resize(0);
            p1 = (len >> 8) & 0xff;
            p2 = len & 0xff;
            card->transmit(0x06, data, p1, p2);
        }
        std::cout << "(" << len << ", " << card->stopTimer() << ")" << std::endl;
    }

    std::cout << "Tranceiving:" << std::endl;

    for (int i = 0; i <= max; i++) {
        len = 50 * i;
        card->startTimer();
        for (int j = 0; j <= repeat; j++) {
            data.resize(len);
            p1 = (len >> 8) & 0xff;
            p2 = len & 0xff;
            card->transmit(0x06, data, p1, p2);
        }
        std::cout << "(" << len << ", " << card->stopTimer() << ")" << std::endl;
    }

}

void cryptoBenchmark()
{
    std::cout << "> starting tests..." << std::endl;

    SmartCard *card = new SmartCard();

    card->setDebug(false);

    if (card == NULL) {
        return;
    }

    if (!card->connect()) {
        return;
    }

    // message stub
    Message msg("test_id", "test_topic", "test_data");

    // key
    bytestring* key = new bytestring(16);
    prng.GenerateBlock(key->BytePtr(), key->size());

    if (!card->storeTopicKey(key)) {
        std::cerr << "Could not store sym key on card" << std::endl;
        return;
    }

    bytestring data;
    int len, repeat = 10;

    std::cout << "HMAC:" << std::endl;
    for (int i = 1; i <= 30; i++) {
        len = 10 * i;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            msg.setData(data);
            msg.hmac(card);
        }
        std::cout << "(" << len << ", " << card->stopTimer() << ")" << std::endl;
    }

    std::cout << "HMAC Verify:" << std::endl;
    for (int i = 1; i <= 30; i++) {
        len = 10 * i;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            msg.setData(data);
            msg.hmac(key);
            msg.hmacVerify(card);
        }
        std::cout << "(" << len << ", " << card->stopTimer() << ")" << std::endl;
    }

    std::cout << "AES ENCRYPT:" << std::endl;
    for (int i = 1; i <= 30; i++) {
        len = 10 * i;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            msg.setData(data);
            msg.aesEncrypt(card);
        }
        std::cout << "(" << len << ", " << card->stopTimer() << ")" << std::endl;
    }

    std::cout << "AES DECRYPT:" << std::endl;
    for (int i = 1; i <= 30; i++) {
        len = 10 * i;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            msg.setData(data);
            msg.aesEncrypt(key);
            msg.aesDecrypt(card);
        }
        std::cout << "(" << len << ", " << card->stopTimer() << ")" << std::endl;
    }

}

void rsaBenchmark()
{
    std::cout << "> starting tests..." << std::endl;

    SmartCard *card = new SmartCard();

    card->setDebug(false);

    // message stub
    Message msg("test_id", "test_topic", "test_data");

    bytestring data;
    int len, repeat = 10;

    RSAKeyPair* serverKeyPair;
    CryptoPP::RSA::PublicKey* clientPub;

    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(prng, 2048);
    serverKeyPair = new RSAKeyPair(params);
    clientPub = serverKeyPair->getPublic();

    // Generate RSA Parameters
    if (card == NULL) {
        return;
    }

    if (!card->connect()) {
        return;
    }

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

    if (file_exists("data/client-pub.key")) {
        clientPub = RSAKeyPair::loadPubKey("data/client-pub.key");
    } else {
        clientPub = card->initialize(serverKeyPair->getPublic());
        RSAKeyPair::savePubKey("data/client-pub.key", clientPub);
    }

    if (clientPub == NULL) {
        std::cerr << card->getError() << std::endl;
        return;
    }

    std::cout << "RSA SIGN:" << std::endl;
    for (int i = 1; i <= 30; i++) {
        len = 10 * i;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            msg.setData(data);
            msg.sign(card);
        }
        std::cout << "(" << len << ", " << card->stopTimer() << ")" << std::endl;
    }

    std::cout << "RSA VERIFY:" << std::endl;
    for (int i = 1; i <= 30; i++) {
        len = 10 * i;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            msg.setData(data);
            msg.sign(serverKeyPair->getPrivate());
            msg.verify(card);
        }
        std::cout << "(" << len << ", " << card->stopTimer() << ")" << std::endl;
    }

    std::cout << "RSA ENCRYPT:" << std::endl;
    for (int i = 1; i <= 30; i++) {
        len = 10 * i;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            msg.setData(data);
            msg.encrypt(card);
        }
        std::cout << "(" << len << ", " << card->stopTimer() << ")" << std::endl;
    }

    std::cout << "RSA DECCRYPT:" << std::endl;
    for (int i = 1; i <= 30; i++) {
        len = 10 * i;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            msg.setData(data);
            msg.encrypt(clientPub);
            msg.decrypt(card);
        }
        std::cout << "(" << len << ", " << card->stopTimer() << ")" << std::endl;
    }

}

void highLevelBenchmark()
{
    std::cout << "> starting tests..." << std::endl;

    SmartCard *card = new SmartCard();

    card->setDebug(true);

    // message stub
    Message msg("test_id", "test_topic", "test_data");

    bytestring data;
    int len, repeat = 10;

    RSAKeyPair* serverKeyPair;
    CryptoPP::RSA::PublicKey* clientPub;

    TopicKeyPair *topic_key_pair = new TopicKeyPair(
        generateKey(TopicKeyPair::KeyLength),
        generateKey(TopicKeyPair::KeyLength)
    );

    // Generate RSA Parameters
    if (card == NULL) {
        return;
    }

    if (!card->connect()) {
        return;
    }

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

    if (file_exists("data/client-pub.key")) {
        clientPub = RSAKeyPair::loadPubKey("data/client-pub.key");
    } else {
        clientPub = card->initialize(serverKeyPair->getPublic());
        RSAKeyPair::savePubKey("data/client-pub.key", clientPub);
    }

    if (clientPub == NULL) {
        std::cerr << card->getError() << std::endl;
        return;
    }

    msg.setData(*topic_key_pair->getValue());
    msg.encrypt(clientPub);
    msg.sign(serverKeyPair->getPrivate());

    std::cout << "HANDLE TOPIC KEY RESPONSE:" << std::endl;
    card->startTimer();
    for (int j = 0; j < repeat; j++) {
        msg.handleTopicKeyResponse(card);
    }
    std::cout << "(" << msg.encode().size() << ", " << card->stopTimer() << ")" << std::endl;
}

/**
 * Eceute message unit tests
 * @param  argc ignored
 * @param  argv ignored
 * @return int reponse code
 */
int main(int argc, char* argv[])
{
    // throughputBenchmark();
    // cryptoBenchmark();
    // rsaBenchmark();
    highLevelBenchmark();

    return 0;
}
