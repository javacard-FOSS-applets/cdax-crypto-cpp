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

        friend std::ostream &operator<< (std::ostream &out, const Message &msg);
        friend class boost::serialization::access;

        void addPKCS7();
        void removePKCS7();

        bytestring generateIV(int length) const;
        bytestring getDataLength() const;

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
        const std::string encode() const;

        const bytestring getPayload() const;

        void setId(bytestring identity);
        bytestring getId() const;

        void setTopic(bytestring topic_name);
        bytestring getTopic() const;

        void setTimestamp(bytestring message_timestamp);
        bytestring getTimestamp() const;

        void setData(bytestring topic_data);
        bytestring getData() const;

        void setSignature(bytestring sig);
        bytestring getSignature() const;

        void aesEncrypt(bytestring* key);
        bool aesDecrypt(bytestring* key);

        void hmac(bytestring* key);
        bool hmacVerify(bytestring* key);

        void encrypt(CryptoPP::RSA::PublicKey* key);
        bool decrypt(CryptoPP::RSA::PrivateKey* key);

        void sign(CryptoPP::RSA::PrivateKey* key);
        bool verify(CryptoPP::RSA::PublicKey* key);

        bool sign(SmartCard* card);
        bool verify(SmartCard* card);

        bool encrypt(SmartCard* card);
        bool decrypt(SmartCard* card);

        bool hmac(SmartCard* card);
        bool hmacVerify(SmartCard* card);

        bool aesEncrypt(SmartCard* card);
        bool aesDecrypt(SmartCard* card);

        bool handleTopicKeyResponse(SmartCard* card);

        bool encode(SmartCard* card);
        bool decode(SmartCard* card);
    };

}
