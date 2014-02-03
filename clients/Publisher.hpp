#pragma once

#include "Client.hpp"

namespace cdax {

    /**
     * Publisher is responsible for collecting topic data and sending
     * it to the appropiate node
     */
    class Publisher : public virtual Client
    {
    public:
        Publisher();
        Publisher(bytestring identity, RSAKeyPair rsa_key_pair);

        virtual void publishMessage(bytestring topic, bytestring data);

        void generateRandom();
    };

}
