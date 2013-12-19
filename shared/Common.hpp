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

    class bytestring : public CryptoPP::SecByteBlock
    {
    private:

        friend std::ostream &operator<< (std::ostream &out, const bytestring &msg);
    public:
        bytestring(size_t size = 0) : CryptoPP::SecByteBlock(size) {};


        bytestring(std::string source);
        bytestring(const char* source);
        const std::string hex();
        const std::string str();

        void clear();
    };


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

        CryptoPP::RSA::PublicKey* getPublic();
        CryptoPP::RSA::PrivateKey* getPrivate();

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
        bytestring encryptionKey;
        bytestring authenticationKey;

    public:
        static const int KeyLength = 16;

        TopicKeyPair();
        TopicKeyPair(std::string source);
        TopicKeyPair(bytestring enc_key, bytestring auth_key);

        bytestring* getEncKey();
        bytestring* getAuthKey();

        std::string toString();
    };

    bytestring stringToSec(std::string str);
    std::string secToString(bytestring block);

    std::string hex(byte val[], size_t len);
    std::string hex(std::string val);
    std::string hex(bytestring val);
    std::string hex(CryptoPP::RSA::PrivateKey key);
    std::string hex(CryptoPP::RSA::PublicKey key);

    std::string randomString(size_t length);
}
