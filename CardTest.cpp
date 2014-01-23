
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


void signatuteTest()
{
    log("> starting tests...");

    SmartCard *card = new SmartCard();

    if (card == NULL) {
        return;
    }

    if (!card->connect()) {
        return;
    }

    card->setDebug(true);

    RSAKeyPair* serverKeyPair;
    CryptoPP::RSA::PublicKey* clientPub;


    // Generate RSA Parameters

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

    /*

    if (clientPub == NULL) {
        log(card->getError());
        return;
    }

    // create message
    Message msg("test_id", "test_topic", "test_data");
    std::cout << msg;

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

    msg.encrypt(serverKeyPair->getPublic());
    log("> message encrypted");
    std::cout << msg;

    msg.setData("test_data");

    msg.encrypt(card);
    log("> message encrypted on card");
    std::cout << msg;

    if (msg.decrypt(serverKeyPair->getPrivate())) {
        log("> message decrypted");
        std::cout << msg;
    }

    msg.encrypt(clientPub);
    log("> message encrypted");
    std::cout << msg;

    if (msg.decrypt(card)) {
        log("> message decrypted on card");
        std::cout << msg;
    }

    CryptoPP::AutoSeededRandomPool prng;
    bytestring* key = new bytestring(16);
    prng.GenerateBlock(key->BytePtr(), key->size());

    std::cout << "> key: " << key->hex() << std::endl;

    if (card->storeTopicKey(key)) {
        log("> stored key on card");

        msg.aesEncrypt(key);
        log("> message encrypted");
        std::cout << msg;

        msg.aesDecrypt(card);
        log("> message decrypted on card");
        std::cout << msg;

        msg.aesEncrypt(card);
        log("> message encrypted on card");
        std::cout << msg;

        msg.aesDecrypt(key);
        log("> message decrypted");
        std::cout << msg;

        msg.hmac(key);
        std::cout << "> signature: " << msg.getSignature().hex() << std::endl;

        if (msg.hmacVerify(card)) {
            log("> messaged hmac verified on card");
        }

        msg.hmac(card);
        std::cout << "> card signature: " << msg.getSignature().hex() << std::endl;

        if (msg.hmacVerify(key)) {
            log("> messaged hmac verified");
        } else {
            log("> could not verify message hmac");
        }
    }

    */

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
