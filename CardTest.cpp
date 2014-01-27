
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


void log(std::string msg)
{
    std::cout << msg << std::endl << line << std::endl;
}

/**
 * Generate AES or HMAC key
 * @param  int length
 * @return bytestring
 */
bytestring* generateKey(size_t length)
{
    CryptoPP::AutoSeededRandomPool prng;
    bytestring* key = new bytestring(length);
    prng.GenerateBlock(key->BytePtr(), key->size());
    return key;
}


void signatuteTest()
{
    log("> starting tests...");

    SmartCard *card = new SmartCard();

    if (card == NULL) {
        return;
    }

    card->setDebug(true);


    if (!card->connect()) {
        return;
    }

    RSAKeyPair* serverKeyPair;
    CryptoPP::RSA::PublicKey* clientPub;

    // create message
    Message msg("test_id", "test_topic", "test_data");

    TopicKeyPair *topic_key_pair = new TopicKeyPair(
        *generateKey(TopicKeyPair::KeyLength),
        *generateKey(TopicKeyPair::KeyLength)
    );

    // Generate RSA Parameters

    // if (file_exists("data/server-priv.key") && file_exists("data/server-pub.key")) {
    //     CryptoPP::RSA::PublicKey* pub = RSAKeyPair::loadPubKey("data/server-pub.key");
    //     CryptoPP::RSA::PrivateKey* priv = RSAKeyPair::loadPrivKey("data/server-priv.key");

    //     serverKeyPair = new RSAKeyPair(pub, priv);
    // } else {
    //     CryptoPP::InvertibleRSAFunction params;
    //     params.GenerateRandomWithKeySize(prng, 2048);
    //     serverKeyPair = new RSAKeyPair(params);

    //     RSAKeyPair::savePrivKey("data/server-priv.key", serverKeyPair->getPrivate());
    //     RSAKeyPair::savePubKey("data/server-pub.key", serverKeyPair->getPublic());
    // }


    // if (file_exists("data/client-pub.key")) {
    //     clientPub = RSAKeyPair::loadPubKey("data/client-pub.key");
    // } else {
    //     clientPub = card->initialize(serverKeyPair->getPublic());
    //     RSAKeyPair::savePubKey("data/client-pub.key", clientPub);
    // }

    // if (clientPub == NULL) {
    //     log(card->getError());
    //     return;
    // }

    // msg.sign(card);
    // log("> message signed on card");

    // if (msg.verify(clientPub)) {
    //     log("> signature verified");
    // }

    // msg.sign(serverKeyPair->getPrivate());
    // log("> message signed");

    // if (msg.verify(card)) {
    //     log("> signature verified on card");
    // }

    // msg.encrypt(serverKeyPair->getPublic());
    // log("> message encrypted");
    // std::cout << msg;

    // msg.setData("test_data");

    // msg.encrypt(card);
    // log("> message encrypted on card");
    // std::cout << msg;

    // if (msg.decrypt(serverKeyPair->getPrivate())) {
    //     log("> message decrypted");
    //     std::cout << msg;
    // }

    // msg.encrypt(clientPub);
    // log("> message encrypted");
    // std::cout << msg;

    // if (msg.decrypt(card)) {
    //     log("> message decrypted on card");
    //     std::cout << msg;
    // }

    // std::cout << "> key: " << topic_key_pair->getEncKey()->hex() << std::endl;

    // if (card->storeTopicKey(topic_key_pair->getValue())) {
    //     log("> stored key on card");

    //     msg.aesEncrypt(topic_key_pair->getEncKey());
    //     log("> message encrypted");
    //     std::cout << msg;

    //     msg.aesDecrypt(card);
    //     log("> message decrypted on card");
    //     std::cout << msg;

    //     msg.aesEncrypt(card);
    //     log("> message encrypted on card");
    //     std::cout << msg;

    //     msg.aesDecrypt(topic_key_pair->getEncKey());
    //     log("> message decrypted");
    //     std::cout << msg;

    //     std::cout << "> key: " << topic_key_pair->getAuthKey()->hex() << std::endl;

    //     msg.hmac(topic_key_pair->getAuthKey());
    //     std::cout << "> signature: " << msg.getSignature().hex() << std::endl;

    //     std::cout << "> key: " << topic_key_pair->getAuthKey()->hex() << std::endl;

    //     if (msg.hmacVerify(card)) {
    //         log("> messaged hmac verified on card");
    //     }

    //     msg.hmac(card);
    //     std::cout << "> card signature: " << msg.getSignature().hex() << std::endl;

    //     if (msg.hmacVerify(topic_key_pair->getAuthKey())) {
    //         log("> messaged hmac verified");
    //     } else {
    //         log("> could not verify message hmac");
    //     }
    // }

    // topic join response
    // msg.setData(*topic_key_pair->getValue());
    // msg.encrypt(clientPub);
    // msg.sign(serverKeyPair->getPrivate());

    // std::cout << "> topic key pair: " << topic_key_pair->getValue()->hex() << std::endl;

    // msg.handleTopicKeyResponse(card);

    // msg.setData("hello");

    // msg.hmac(topic_key_pair->getAuthKey());
    // std::cout << "> signature: " << msg.getSignature().hex() << std::endl;

    // msg.hmac(topic_key_pair->getAuthKey());
    // std::cout << "> signature: " << msg.getSignature().hex() << std::endl;

    // msg.aesEncrypt(topic_key_pair->getEncKey());
    // msg.aesDecrypt(card);

    // if (msg.hmacVerify(card)) {
    //     log("> messaged hmac verified on card");
    // }

    std::cout << msg;

    card->storeTopicKey(topic_key_pair->getValue());

    // for (int i = 0; i < 1; i++) {
    //     msg.hmac(card);

    //     if (!msg.hmacVerify(topic_key_pair->getAuthKey())) {
    //         std::cout << "ERROR!!!!!!";
    //     }
    // }

    // for (int i = 0; i < 1; i++) {
    //     msg.aesEncrypt(card);

    //     if (!msg.aesDecrypt(topic_key_pair->getEncKey())) {
    //         std::cout << "ERROR!!!!!!";
    //     }
    // }

    msg.encode(card);
    std::cout << msg;

    msg.decode(card);
    std::cout << msg;
}

/**
 * Eceute message unit tests
 * @param  argc ignored
 * @param  argv ignored
 * @return int reponse code
 */
int main(int argc, char* argv[])
{
    signatuteTest();

    return 0;
}
