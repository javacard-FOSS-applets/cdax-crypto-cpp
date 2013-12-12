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

// a portable text archive model
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

// non-portable native binary archive
// #include <boost/archive/binary_oarchive.hpp>
// #include <boost/archive/binary_iarchive.hpp>

#include "../card/SmartCard.hpp"
#include "Common.hpp"

namespace cdax {

    /**
     * Message class, container of a single unit of topic data and possible
     * security attributes. This class is responsible for all cryptographic
     * functionalities that are applied to its attribute contents.
     */
    class Message
    {
    private:
        // sender identity
        std::string id;

        // topic name
        std::string topic;

        // topic data or message payload
        std::string data;

        // RSA signature or HMAC
        std::string signature;

        // time of message creation
        std::time_t timestamp;

        // AES encryption initialisation vector
        CryptoPP::SecByteBlock iv;

        void generateIV(int length);
        std::string applyCipher(CryptoPP::StreamTransformation &t);
        std::string getPayloadData();

        CryptoPP::SecByteBlock getIV();
        void setIV(CryptoPP::SecByteBlock sec_iv);

        friend std::ostream &operator<< (std::ostream &out, const Message &msg);
        friend class boost::serialization::access;

        /**
         * Encode message content to boost archive model
         */
        template<class Archive>
        void save(Archive & ar, const unsigned int version) const
        {
            ar << this->id;
            ar << this->topic;
            ar << this->data;
            ar << this->signature;

            std::string tmp_timestamp = boost::lexical_cast<std::string>(this->timestamp);
            ar << tmp_timestamp;

            std::string tmp_iv = secToString(this->iv);
            ar << tmp_iv;
        }

        /**
         * Decode message contents from boost archive model
         */
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
            this->iv = stringToSec(tmp_iv);
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

        void encryptAndHMAC(CryptoPP::SecByteBlock key);
        bool verifyAndDecrypt(CryptoPP::SecByteBlock key);

        void encrypt(CryptoPP::SecByteBlock key);
        bool decrypt(CryptoPP::SecByteBlock key);

        void hmac(CryptoPP::SecByteBlock key);
        bool verify(CryptoPP::SecByteBlock key);

        void encrypt(CryptoPP::RSA::PublicKey key);
        bool decrypt(CryptoPP::RSA::PrivateKey key);

        void sign(CryptoPP::RSA::PrivateKey key);
        bool verify(CryptoPP::RSA::PublicKey key);

        void signOnCard(SmartCard *card);
    };

}
