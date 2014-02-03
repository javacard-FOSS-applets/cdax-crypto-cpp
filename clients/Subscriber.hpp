#pragma once

#include "Client.hpp"
#include "../shared/Message.hpp"

namespace cdax {

    /**
     * CDAX subscriber class, responsible for receiving and logging topic data
     */
    class Subscriber : public virtual Client
    {
    protected:
        virtual Message handle(Message request);

    public:
        Subscriber();
        Subscriber(bytestring identity, std::string port_number, RSAKeyPair rsa_key_pair);
    };

}
