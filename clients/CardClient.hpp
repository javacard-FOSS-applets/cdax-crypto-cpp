#pragma once

#include "Client.hpp"

namespace cdax {

    class CardClient : public virtual Client
    {
    protected:
        SmartCard *card;

    public:
        CryptoPP::RSA::PublicKey initKeys(CryptoPP::RSA::PublicKey server_key);

        void addTopic(bytestring topic_name, std::string topic_port);
    };

}
