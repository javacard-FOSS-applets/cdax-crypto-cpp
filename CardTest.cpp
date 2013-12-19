
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

    // Generate RSA Parameters
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(prng, 2048);
    RSAKeyPair* keyPair = new RSAKeyPair(params);

    CryptoPP::RSA::PublicKey* clientPub = card->initialize(keyPair->getPublic());

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
