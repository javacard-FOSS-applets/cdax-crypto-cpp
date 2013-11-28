#pragma once

#include "Client.hpp"

namespace cdax {

    /**
     * Publisher is responsible for collecting topic data and sending
     * it to the appropiate node
     */
    class Publisher : public Client
    {
    public:
        Publisher(std::string identity, RSAKeyPair rsa_key_pair);
        void generateRandom();
    };

}
