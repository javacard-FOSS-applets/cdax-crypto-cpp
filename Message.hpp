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

        std::string id;
        std::string topic;

        std::string data;
        std::string signature;

        std::time_t timestamp;

        CryptoPP::SecByteBlock iv;

        void generateIV(int length);
        std::string applyCipher(CryptoPP::StreamTransformation &t);
        std::string getPayloadData();

        CryptoPP::SecByteBlock getIV();
        void setIV(CryptoPP::SecByteBlock sec_iv);

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
        }

        template<class Archive>
        void serialize(Archive& ar, const unsigned int file_version)
        {
            boost::serialization::split_member(ar, *this, file_version);
        }

    public:
        Message();

        Message(std::string identity, std::string topic_name, std::string topic_data);

        void setId(std::string identity);
        std::string getId();

        void setTopic(std::string topic_name);
        std::string getTopic();

        void setData(std::string topic_data);
        std::string getData();

        std::string getSignature();

        void hmacAndEncrypt(CryptoPP::SecByteBlock key);
        bool decryptAndVerify(CryptoPP::SecByteBlock key);

        void encrypt(CryptoPP::SecByteBlock key);
        bool decrypt(CryptoPP::SecByteBlock key);

        void hmac(CryptoPP::SecByteBlock key);
        bool verify(CryptoPP::SecByteBlock key);

        void encrypt(CryptoPP::RSA::PublicKey key);
        bool decrypt(CryptoPP::RSA::PrivateKey key);

        void sign(CryptoPP::RSA::PrivateKey key);
        bool verify(CryptoPP::RSA::PublicKey key);
    };

}
