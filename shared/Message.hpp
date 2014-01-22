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
#include <boost/asio.hpp>

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
        bytestring id;

        // topic name
        bytestring topic;

        // topic data or message payload
        bytestring data;

        // RSA signature or HMAC
        bytestring signature;

        // time of message creation
        std::time_t timestamp;

        // AES encryption initialisation vector
        bytestring iv;

        void generateIV(int length);

        bytestring getIV();
        void setIV(bytestring sec_iv);

        friend std::ostream &operator<< (std::ostream &out, const Message &msg);
        friend class boost::serialization::access;

        /**
         * Encode message content to boost archive model
         */
        template<class Archive>
        void save(Archive & ar, const unsigned int version) const
        {
            ar << this->encode();
        }

        /**
         * Decode message content to boost archive model
         */
        template<class Archive>
        void load(Archive & ar, const unsigned int version)
        {
            std::string encoded;
            ar >> encoded;
            this->decode(encoded);
        }

        template<class Archive>
        void serialize(Archive& ar, const unsigned int file_version)
        {
            boost::serialization::split_member(ar, *this, file_version);
        }

    public:
        Message();

        Message(bytestring identity, bytestring topic_name, bytestring topic_data);

        void decode(std::string encoded);
        const std::string encode(bool all = true) const;

        void setId(bytestring identity);
        bytestring getId();

        void setTopic(bytestring topic_name);
        bytestring getTopic();

        void setData(bytestring topic_data);
        bytestring getData();

        bytestring getSignature();

        void encryptAndHMAC(bytestring* key);
        bool verifyAndDecrypt(bytestring* key);

        void encrypt(bytestring* key);
        bool decrypt(bytestring* key);

        void hmac(bytestring* key);
        bool verify(bytestring* key);

        void encrypt(CryptoPP::RSA::PublicKey* key);
        bool decrypt(CryptoPP::RSA::PrivateKey* key);

        void sign(CryptoPP::RSA::PrivateKey* key);
        bool verify(CryptoPP::RSA::PublicKey* key);

        bool signOnCard(SmartCard* card);
        bool verifyOnCard(SmartCard* card);

        bool encryptOnCard(SmartCard* card);
        bool decryptOnCard(SmartCard* card);

        bool hmacOnCard(SmartCard* card);
        bool verifyHMACOnCard(SmartCard* card);

        bool aesEncryptOnCard(SmartCard* card);
        bool aesDecryptOnCard(SmartCard* card);
    };

}
