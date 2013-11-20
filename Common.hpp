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

    namespace Cipher
    {
        enum CipherType {
            Salsa20,
            AES_CBC,
            AES_GCM,
            RSA
        };

        static const char* CipherString[] = {
            "Salsa 20",
            "AES CBC Mode",
            "AES Authenticated GCM",
            "RSA"
        };
    }

    class RSAKeyPair
    {
    public:
        RSAKeyPair();
        RSAKeyPair(CryptoPP::InvertibleRSAFunction params);

        CryptoPP::RSA::PublicKey getPublic();
        CryptoPP::RSA::PrivateKey getPrivate();

    private:
        CryptoPP::RSA::PublicKey publicKey;
        CryptoPP::RSA::PrivateKey privateKey;
    };

    class TopicKeyPair
    {
    public:
        TopicKeyPair();
        TopicKeyPair(std::string source);
        TopicKeyPair(CryptoPP::SecByteBlock enc_key, CryptoPP::SecByteBlock auth_key);

        CryptoPP::SecByteBlock getEncKey();
        CryptoPP::SecByteBlock getAuthKey();

        std::string toString();

    private:
        CryptoPP::SecByteBlock encryptionKey;
        CryptoPP::SecByteBlock authenticationKey;

        friend class boost::serialization::access;

        template<class Archive>
        void save(Archive & ar, const unsigned int version) const
        {
            std::string tmp_enc = std::string(this->encryptionKey.begin(), this->encryptionKey.end());
            ar << tmp_enc;

            std::string tmp_auth = std::string(this->authenticationKey.begin(), this->authenticationKey.end());
            ar << tmp_auth;
        }

        template<class Archive>
        void load(Archive & ar, const unsigned int version)
        {
            std::string tmp_enc;
            ar >> tmp_enc;
            this->encryptionKey = CryptoPP::SecByteBlock(tmp_enc.size());
            this->encryptionKey.Assign((const unsigned char*) tmp_enc.c_str(), tmp_enc.size());

            std::string tmp_auth;
            ar >> tmp_auth;
            this->authenticationKey = CryptoPP::SecByteBlock(tmp_auth.size());
            this->authenticationKey.Assign((const unsigned char*) tmp_auth.c_str(), tmp_auth.size());
        }

        template<class Archive>
        void serialize(Archive& ar, const unsigned int file_version)
        {
            boost::serialization::split_member(ar, *this, file_version);
        }
    };

    std::string hex(std::string val);
    std::string hex(CryptoPP::SecByteBlock val);
    std::string hex(CryptoPP::RSA::PrivateKey key);
    std::string hex(CryptoPP::RSA::PublicKey key);

    std::string randomString(size_t length);
}
