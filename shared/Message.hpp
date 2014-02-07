#pragma once

#include <cstdlib>
#include <string>
#include <iostream>
#include <sstream>
#include <ctime>

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/filters.h>

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
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

        bytestring generateIV(int length);
        bytestring getDataLength();

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
        const bytestring getId() const;

        void setTopic(bytestring topic_name);
        const bytestring getTopic() const;

        void setTimestamp(bytestring message_timestamp);
        const bytestring getTimestamp() const;
        const std::time_t getRawTimestamp() const;

        void setData(bytestring topic_data);
        const bytestring getData() const;

        void setSignature(bytestring sig);
        const bytestring getSignature() const;

        void aesEncrypt(bytestring key);
        bool aesDecrypt(bytestring key);

        void hmac(bytestring key);
        bool hmacVerify(bytestring key);

        void encrypt(CryptoPP::RSA::PublicKey key);
        bool decrypt(CryptoPP::RSA::PrivateKey key);

        void sign(CryptoPP::RSA::PrivateKey key);
        bool verify(CryptoPP::RSA::PublicKey key);

        bool sign(SmartCard* card);
        bool verify(SmartCard* card);

        bool encrypt(SmartCard* card);
        bool decrypt(SmartCard* card);

        bool hmac(SmartCard* card, size_t key_index = 0);
        bool hmacVerify(SmartCard* card, size_t key_index = 0);

        bool aesEncrypt(SmartCard* card, size_t key_index = 0);
        bool aesDecrypt(SmartCard* card, size_t key_index = 0);

        bool handleTopicKeyResponse(SmartCard* card, size_t key_index = 0);

        bool encode(SmartCard* card, size_t key_index = 0);
        bool decode(SmartCard* card, size_t key_index = 0);
    };

}
