#pragma once

#include "Client.hpp"
#include "../shared/Message.hpp"

namespace cdax {

    /**
     * CDAX subscriber class, responsible for receiving and logging topic data
     */
    class Subscriber : public Client
    {
    protected:
        Message handle(Message request);

    public:
        Subscriber(std::string identity, std::string port_number, RSAKeyPair rsa_key_pair);
    };

}
