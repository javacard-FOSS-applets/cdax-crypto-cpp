
#include <string>
#include <cstdlib>
#include <iostream>

#include <cryptopp/files.h>

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

void saveKey(std::string filename, CryptoPP::BufferedTransformation& queue)
{

    CryptoPP::FileSink file(filename.c_str());

    queue.CopyTo(file);
    file.MessageEnd();
}

void saveKey(std::string filename, CryptoPP::RSA::PublicKey* key)
{
    CryptoPP::ByteQueue queue;
    key->Save(queue);
    saveKey(filename, queue);
}

void saveKey(std::string filename, CryptoPP::RSA::PrivateKey* key)
{
    CryptoPP::ByteQueue queue;
    key->Save(queue);
    saveKey(filename, queue);
}

void loadKey(std::string filename, CryptoPP::CryptoMaterial* key)
{
    CryptoPP::ByteQueue queue;

    CryptoPP::FileSource file(filename.c_str(), true);

    file.TransferTo(queue);
    queue.MessageEnd();

    key->Load(queue);
}

CryptoPP::RSA::PublicKey loadPubKey(std::string filename)
{
    CryptoPP::RSA::PublicKey key;
    loadKey(filename, &key);
    return key;
}

CryptoPP::RSA::PrivateKey loadPrivKey(std::string filename)
{
    CryptoPP::RSA::PrivateKey key;
    loadKey(filename, &key);
    return key;
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

    saveKey("data/server-priv.key", keyPair->getPrivate());
    saveKey("data/server-pub.key", keyPair->getPublic());

    CryptoPP::RSA::PublicKey pub = loadPubKey("data/server-priv.key");
    CryptoPP::RSA::PrivateKey priv = loadPrivKey("data/server-priv.key");

    // CryptoPP::RSA::PublicKey* clientPub = card->initialize(keyPair->getPublic());

    // if (clientPub == NULL) {
    //     log(card->getError());
    //     return;
    // }

    // create message
    Message msg("test_id", "test_topic", "test_data");

    msg.signOnCard(card);

    // if (msg.verify(clientPub)) {
    //     log("> signatures matched");
    // } else {
    //     log("> signatures did not match");
    //     log("> signature: " + msg.getSignature().hex());
    // }
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
