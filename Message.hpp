#pragma once

#include <cstdlib>
#include <string>
#include <iostream>
#include <sstream>
#include <ctime>

#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/salsa.h>
#include <cryptopp/filters.h>

#include <boost/lexical_cast.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include "Common.hpp"

namespace cdax {

    class Message
    {
    private:
        friend std::ostream &operator<< (std::ostream &out, const Message &msg);
        friend class boost::serialization::access;

        template<class Archive>
        void save(Archive & ar, const unsigned int version) const
        {
            ar << this->id;
            ar << this->topic;
            ar << this->data;
            ar << this->signature;

            std::string tmp_timestamp = boost::lexical_cast<std::string>(this->timestamp);
            ar << tmp_timestamp;

            std::string tmp_iv = std::string(this->iv.begin(), this->iv.end());
            ar << tmp_iv;

            std::string tmp_cipher = boost::lexical_cast<std::string>(this->cipher);
            ar << tmp_cipher;

            std::string tmp_enc = boost::lexical_cast<std::string>(encrypted);
            ar << tmp_enc;

            std::string tmp_auth = boost::lexical_cast<std::string>(authenticated);
            ar << tmp_auth;
        }

        template<class Archive>
        void load(Archive & ar, const unsigned int version)
        {
            ar >> this->id;
            ar >> this->topic;
            ar >> this->data;
            ar >> this->signature;

            std::string tmp_timestamp;
            ar >> tmp_timestamp;
            this->timestamp = boost::lexical_cast<int>(tmp_timestamp);

            std::string tmp_iv;
            ar >> tmp_iv;
            this->iv = CryptoPP::SecByteBlock(tmp_iv.size());
            this->iv.Assign((const unsigned char*) tmp_iv.c_str(), tmp_iv.size());

            std::string tmp_cipher;
            ar >> tmp_cipher;
            int c = boost::lexical_cast<int>(tmp_cipher);
            this->cipher = static_cast<Cipher::CipherType>(c);

            std::string tmp_enc;
            ar >> tmp_enc;
            this->encrypted = boost::lexical_cast<bool>(tmp_enc);

            std::string tmp_auth;
            ar >> tmp_auth;
            this->authenticated = boost::lexical_cast<bool>(tmp_auth);
        }

        template<class Archive>
        void serialize(Archive& ar, const unsigned int file_version)
        {
            boost::serialization::split_member(ar, *this, file_version);
        }

        std::string id;
        std::string topic;

        std::string data;
        std::string signature;

        std::time_t timestamp;

        CryptoPP::SecByteBlock iv;
        Cipher::CipherType cipher = Cipher::AES_CBC;

        bool encrypted = false;
        bool authenticated = false;

        void generateIV(int length);
        std::string applyCipher(CryptoPP::StreamTransformation &t);
        std::string getPayloadData();

        CryptoPP::SecByteBlock getIV();
        void setIV(CryptoPP::SecByteBlock sec_iv);

    public:
        Message();

        void setCipher(Cipher::CipherType c);
        Cipher::CipherType getCipher();

        void setId(std::string d);
        std::string getId();

        void setTopic(std::string d);
        std::string getTopic();

        void setData(std::string d);
        std::string getData();

        std::string getSignature();

        void encrypt(CryptoPP::SecByteBlock key);
        void decrypt(CryptoPP::SecByteBlock key);

        void sign(CryptoPP::SecByteBlock key);
        void verify(CryptoPP::SecByteBlock key);

        void encrypt(CryptoPP::RSA::PublicKey key);
        void decrypt(CryptoPP::RSA::PrivateKey key);

        void sign(CryptoPP::RSA::PrivateKey key);
        void verify(CryptoPP::RSA::PublicKey key);

    };

}
