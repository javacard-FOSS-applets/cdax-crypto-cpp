
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

    RSAKeyPair* keyPair;
    CryptoPP::RSA::PublicKey* clientPub;

    // Generate RSA Parameters

    if (file_exists("data/server-priv.key") && file_exists("data/server-pub.key")) {
        CryptoPP::RSA::PublicKey* pub = RSAKeyPair::loadPubKey("data/server-pub.key");
        CryptoPP::RSA::PrivateKey* priv = RSAKeyPair::loadPrivKey("data/server-priv.key");

        keyPair = new RSAKeyPair(pub, priv);
    } else {
        CryptoPP::InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(prng, 2048);
        keyPair = new RSAKeyPair(params);

        RSAKeyPair::savePrivKey("data/server-priv.key", keyPair->getPrivate());
        RSAKeyPair::savePubKey("data/server-pub.key", keyPair->getPublic());
    }

    if (file_exists("data/client-pub.key")) {
        clientPub = RSAKeyPair::loadPubKey("data/client-pub.key");
    } else {
        clientPub = card->initialize(keyPair->getPublic());
        RSAKeyPair::savePubKey("data/client-pub.key", clientPub);
    }

    if (clientPub == NULL) {
        log(card->getError());
        return;
    }

    // create message
    Message msg("test_id", "test_topic", "test_data");

    msg.signOnCard(card);

    if (msg.verify(clientPub)) {
        log("> signatures matched");
    } else {
        log("> signatures did not match");
        log("> signature: " + msg.getSignature().hex());
    }
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
