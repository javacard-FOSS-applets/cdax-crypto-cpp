#pragma once

#include <string>

#include "bytestring.hpp"

namespace cdax {

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
        TopicKeyPair(bytestring source);
        TopicKeyPair(bytestring enc_key, bytestring auth_key);

        bytestring getEncKey();
        bytestring getAuthKey();

        bytestring getValue();
        std::string toString();
    };

}
