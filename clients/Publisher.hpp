#pragma once

#include "Client.hpp"

namespace cdax {

    class Publisher : public Client
    {
    public:
        Publisher(std::string identity, RSAKeyPair rsa_key_pair);
        void generateRandom();
    };

}
