
#include <string>
#include <cstdlib>
#include <iostream>
#include <unistd.h>
#include <fstream>

#include "card/SmartCard.hpp"
#include "shared/Message.hpp"

using namespace cdax;

CryptoPP::AutoSeededRandomPool prng;
const std::string DIRECTORY = "../../paper/shapes/data/";

bytestring generateKey(size_t length)
{
    CryptoPP::AutoSeededRandomPool prng;
    bytestring key(length);
    prng.GenerateBlock(key.BytePtr(), key.size());
    return key;
}

void logTime(std::ofstream& file, SmartCard *card, int len)
{
    file << len << "\t" << card->getTimerMean() << "\t" << card->getTimerStdev() << std::endl;
    std::cout << "> " << len << " in " << card->getTimerMean() << " +- " << card->getTimerStdev() << std::endl;
}

void openLogFile(std::ofstream& file, const std::string name)
{
    if (file.is_open()) {
        file << std::endl;
        file.close();
    }

    file.open (DIRECTORY + name);
    file << "bytes\tmilliseconds\terror" << std::endl;
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
    // 16 * 64 = 1024 bytes
    int len, start = 0, repeat = 10, step = 16, max = 64;
    byte p1, p2;

    std::ofstream file;
    openLogFile(file, "transmit.dat");

    std::cout << "Transmitting:" << std::endl;

    for (int i = start; i <= max; i++) {
        len = step * i;
        card->startTimer();
        for (int j = 0; j <= repeat; j++) {
            data.resize(len);
            card->transmit(0x05, data);
        }
        logTime(file, card, len);
    }

    openLogFile(file, "receive.dat");

    std::cout << "Receiving:" << std::endl;

    for (int i = start; i <= max; i++) {
        len = step * i;
        card->startTimer();
        for (int j = 0; j <= repeat; j++) {
            data.resize(0);
            p1 = (len >> 8) & 0xff;
            p2 = len & 0xff;
            card->transmit(0x06, data, p1, p2);
        }
        logTime(file, card, len);
    }

    openLogFile(file, "tranceive.dat");

    std::cout << "Tranceiving:" << std::endl;

    for (int i = start; i <= max; i++) {
        len = step * i;
        card->startTimer();
        for (int j = 0; j <= repeat; j++) {
            data.resize(len);
            p1 = (len >> 8) & 0xff;
            p2 = len & 0xff;
            card->transmit(0x06, data, p1, p2);
        }
        logTime(file, card, len);
    }

    file << std::endl;
    file.close();

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
    bytestring key(16);
    prng.GenerateBlock(key.BytePtr(), key.size());

    if (!card->storeTopicKey(key)) {
        std::cerr << "Could not store sym key on card" << std::endl;
        return;
    }

    bytestring data;
    // 16 * 64 = 1024 bytes
    int len, start = 1, repeat = 1, step = 16, max = 64;

    std::ofstream file;
    openLogFile(file, "hmac.dat");

    std::cout << "HMAC:" << std::endl;
    for (int i = start; i <= max; i++) {
        len = step * i;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            msg.setData(data);
            msg.hmac(card);
        }
        logTime(file, card, len);
    }

    openLogFile(file, "hmac_verify.dat");

    std::cout << "HMAC Verify:" << std::endl;
    for (int i = start; i <= max; i++) {
        len = step * i;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            msg.setData(data);
            msg.hmac(key);
            msg.hmacVerify(card);
        }
        logTime(file, card, len);
    }

    openLogFile(file, "aes_enc.dat");

    std::cout << "AES ENCRYPT:" << std::endl;
    for (int i = start; i <= max; i++) {
        len = step * i;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            msg.setData(data);
            msg.aesEncrypt(card);
        }
        logTime(file, card, len);
    }

    openLogFile(file, "aes_dec.dat");

    std::cout << "AES DECRYPT:" << std::endl;
    for (int i = start; i <= max; i++) {
        len = step * i;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            msg.setData(data);
            msg.aesEncrypt(key);
            msg.aesDecrypt(card);
        }
        logTime(file, card, len);
    }

    file << std::endl;
    file.close();

}

void rsaBenchmark()
{
    std::cout << "> starting tests..." << std::endl;

    SmartCard *card = new SmartCard();

    card->setDebug(false);

    // message stub
    Message msg("test_id", "test_topic", "test_data");

    bytestring data;
    // the maximum for this public key is 245 bytes (8 * 30 = 240)
    int len, start = 1, repeat = 10, step = 8, max = 30;
    std::ofstream file;

    RSAKeyPair serverKeyPair;
    CryptoPP::RSA::PublicKey clientPub;

    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(prng, 2048);
    serverKeyPair = RSAKeyPair(params);
    clientPub = serverKeyPair.getPublic();

    // Generate RSA Parameters
    if (card == NULL) {
        return;
    }

    if (!card->connect()) {
        return;
    }

    if (file_exists("data/server-priv.key") && file_exists("data/server-pub.key")) {
        CryptoPP::RSA::PublicKey pub = RSAKeyPair::loadPubKey("data/server-pub.key");
        CryptoPP::RSA::PrivateKey priv = RSAKeyPair::loadPrivKey("data/server-priv.key");

        serverKeyPair = RSAKeyPair(pub, priv);
    } else {
        CryptoPP::InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(prng, 2048);
        serverKeyPair = RSAKeyPair(params);

        RSAKeyPair::saveKey("data/server-priv.key", serverKeyPair.getPrivate());
        RSAKeyPair::saveKey("data/server-pub.key", serverKeyPair.getPublic());
    }

    if (file_exists("data/client-pub.key")) {
        clientPub = RSAKeyPair::loadPubKey("data/client-pub.key");
    } else {
        clientPub = card->initialize(serverKeyPair.getPublic());
        RSAKeyPair::saveKey("data/client-pub.key", clientPub);
    }

    openLogFile(file, "rsa_sign.dat");

    std::cout << "RSA SIGN:" << std::endl;
    for (int i = start; i <= max; i++) {
        len = step * i;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            msg.setData(data);
            msg.sign(card);
        }
        logTime(file, card, len);
    }

    openLogFile(file, "rsa_verify.dat");

    std::cout << "RSA VERIFY:" << std::endl;
    for (int i = start; i <= max; i++) {
        len = step * i;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            msg.setData(data);
            msg.sign(serverKeyPair.getPrivate());
            msg.verify(card);
        }
        logTime(file, card, len);
    }

    openLogFile(file, "rsa_enc.dat");

    std::cout << "RSA ENCRYPT:" << std::endl;
    for (int i = start; i <= max; i++) {
        len = step * i;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            msg.setData(data);
            msg.encrypt(card);
        }
        logTime(file, card, len);
    }

    openLogFile(file, "rsa_dec.dat");

    std::cout << "RSA DECCRYPT:" << std::endl;
    for (int i = start; i <= max; i++) {
        len = step * i;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            msg.setData(data);
            msg.encrypt(clientPub);
            msg.decrypt(card);
        }
        logTime(file, card, len);
    }

    file << std::endl;
    file.close();
}

void highLevelBenchmark()
{
    std::cout << "> starting tests..." << std::endl;

    SmartCard *card = new SmartCard();

    card->setDebug(false);

    // message stub
    Message msg("test_id", "test_topic", "test_data");

    bytestring data;
    int len, start = 1, repeat = 10, step = 16, max = 64;
    std::ofstream file;

    RSAKeyPair serverKeyPair;
    CryptoPP::RSA::PublicKey clientPub;

    TopicKeyPair topic_key_pair = TopicKeyPair(
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
        CryptoPP::RSA::PublicKey pub = RSAKeyPair::loadPubKey("data/server-pub.key");
        CryptoPP::RSA::PrivateKey priv = RSAKeyPair::loadPrivKey("data/server-priv.key");

        serverKeyPair = RSAKeyPair(pub, priv);
    } else {
        CryptoPP::InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(prng, 2048);
        serverKeyPair = RSAKeyPair(params);

        RSAKeyPair::saveKey("data/server-priv.key", serverKeyPair.getPrivate());
        RSAKeyPair::saveKey("data/server-pub.key", serverKeyPair.getPublic());
    }

    if (file_exists("data/client-pub.key")) {
        clientPub = RSAKeyPair::loadPubKey("data/client-pub.key");
    } else {
        clientPub = card->initialize(serverKeyPair.getPublic());
        RSAKeyPair::saveKey("data/client-pub.key", clientPub);
    }

    msg.setData("topic_join");
    len = msg.getPayload().size();

    openLogFile(file, "topic_key_request.dat");

    std::cout << "SIGN TOPIC KEY REQUEST:" << std::endl;
    card->startTimer();
    for (int j = 0; j < repeat; j++) {
        msg.sign(card);
    }
    logTime(file, card, len);

    msg.setData(topic_key_pair.getValue());
    msg.encrypt(clientPub);
    msg.sign(serverKeyPair.getPrivate());
    len = msg.getPayload().size();

    openLogFile(file, "topic_key_response.dat");

    std::cout << "HANDLE TOPIC KEY RESPONSE:" << std::endl;
    card->startTimer();
    for (int j = 0; j < repeat; j++) {
        msg.handleTopicKeyResponse(card);
    }
    logTime(file, card, len);

    msg.setSignature("");

    openLogFile(file, "topic_encode.dat");

    std::cout << "TOPIC ENCODE:" << std::endl;
    for (int i = start; i <= max; i++) {
        len = step * i;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            msg.setData(data);
            msg.encode(card);
        }
        logTime(file, card, len);
    }

    openLogFile(file, "topic_decode.dat");

    std::cout << "TOPIC DECODE:" << std::endl;
    for (int i = start; i <= max; i++) {
        len = step * i;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            msg.setData(data);
            msg.aesEncrypt(topic_key_pair.getEncKey());
            msg.hmac(topic_key_pair.getAuthKey());
            msg.decode(card);
        }
        logTime(file, card, len);
    }

    file << std::endl;
    file.close();

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
    cryptoBenchmark();
    // rsaBenchmark();
    // highLevelBenchmark();

    return 0;
}
