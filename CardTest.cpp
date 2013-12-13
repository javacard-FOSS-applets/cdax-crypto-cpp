
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


SmartCard* getCard()
{
    SmartCard *card = new SmartCard();

    if (!card->selectReader()) {
        log(card->getError());
        return NULL;
    }

    if (!card->waitForCard()) {
        log(card->getError());
        return NULL;
    }

    return card;
}

bool storePrivate(SmartCard *card, RSAKeyPair keyPair)
{
    if (!card->storePrivateKey(keyPair.getPrivate())) {
        log(card->getError());
        return false;
    }

    log("wrote private key to card");

    return true;
}

/**
 * Eceute message unit tests
 * @param  argc ignored
 * @param  argv ignored
 * @return int reponse code
 */
int main(int argc, char* argv[])
{
    log("> starting tests...");

    SmartCard *card = getCard();

    if (card == NULL) {
        return 1;
    }

    // Generate RSA Parameters
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(prng, 1024);
    RSAKeyPair keyPair(params);

    storePrivate(card, keyPair);

    // create message
    Message msg("test_id", "test_topic", "test_data");

    msg.sign(keyPair.getPrivate());
    std::string device_sig = msg.getSignature();

    msg.signOnCard(card);
    std::string card_sig = msg.getSignature();

    if (device_sig.compare(card_sig) != 0) {
        log("> signatures did not match");
        log("> device: " + hex(device_sig) + "\ncard: " + hex(card_sig));
    } else {
        log("> signatures matched");
    }

    return 0;
}
