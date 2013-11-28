#pragma once

#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <string>

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/tuple/tuple.hpp>
#include <cryptopp/osrng.h>
#include <cryptopp/queue.h>
#include <cryptopp/rsa.h>

#define RED      "\033[22;31m"
#define GREEN    "\033[22;32m"
#define YELLOW   "\033[22;33m"
#define BLUE     "\033[22;34m"
#define MAGENTA  "\033[22;35m"
#define CYAN     "\033[22;36m"

namespace cdax {

    /**
     * Container class of a RSA keypair, holds the default keylength
     */
    class RSAKeyPair
    {
    private:
        CryptoPP::RSA::PublicKey publicKey;
        CryptoPP::RSA::PrivateKey privateKey;

    public:
        static const int KeyLength = 1024;

        RSAKeyPair();
        RSAKeyPair(CryptoPP::InvertibleRSAFunction params);

        CryptoPP::RSA::PublicKey getPublic();
        CryptoPP::RSA::PrivateKey getPrivate();

    };

    /**
     * ciontainer class of a Topic keypair.
     * The encrytpion key is used for AES CBC encryption and
     * HMAC generation and is distributed to CDAX clients.
     * The authentication key us used for message HMAC generation
     * and is distributed to CDAX clients and nodes.
     */
    class TopicKeyPair
    {
    private:
        CryptoPP::SecByteBlock encryptionKey;
        CryptoPP::SecByteBlock authenticationKey;

    public:
        static const int KeyLength = 16;

        TopicKeyPair();
        TopicKeyPair(std::string source);
        TopicKeyPair(CryptoPP::SecByteBlock enc_key, CryptoPP::SecByteBlock auth_key);

        CryptoPP::SecByteBlock getEncKey();
        CryptoPP::SecByteBlock getAuthKey();

        std::string toString();
    };

    CryptoPP::SecByteBlock stringToSec(std::string str);
    std::string secToString(CryptoPP::SecByteBlock block);

    std::string hex(std::string val);
    std::string hex(CryptoPP::SecByteBlock val);
    std::string hex(CryptoPP::RSA::PrivateKey key);
    std::string hex(CryptoPP::RSA::PublicKey key);

    std::string randomString(size_t length);
}
