
#include "Subscriber.hpp"

namespace cdax {

    Subscriber::Subscriber(std::string identity, std::string port_number, RSAKeyPair rsa_key_pair)
    {
        this->id = identity;
        this->port = port_number;
        this->key_pair = rsa_key_pair;

        // terminal log color
        this->color = GREEN;
    }

    Message Subscriber::handle(Message msg)
    {
        // verify with the node topic key
        if (!msg.verify(this->topic_keys[msg.getTopic()].getAuthKey())) {

            this->log("could not verify:", msg);

            return Message();
        }

        // AES decrypt and verify hmac with end-to-end topic key
        if (!msg.decryptAndVerify(this->topic_keys[msg.getTopic()].getEncKey())) {

            this->log("could not decrypt and verify:", msg);

            return Message();
        }

        this->log("received:", msg);

        return Message();
    }

}
