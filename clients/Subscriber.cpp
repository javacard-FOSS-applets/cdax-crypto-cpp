
#include "Subscriber.hpp"

namespace cdax {

    /**
     * Construct a new subscriber, given its name,
     * RSA key pair and the port number to listen on
     * @param string identity name of the subscriber
     * @param string port_number port number as string
     * @param string rsa_key_pair
     */
    Subscriber::Subscriber(bytestring identity, std::string port_number, RSAKeyPair rsa_key_pair)
    {
        this->id = identity;
        this->port = port_number;
        this->key_pair = rsa_key_pair;

        // terminal log color
        this->color = GREEN;
    }

    /**
     * Handle topic data messages, verify the two HMACs and decrypt topic data
     * @param   Message msg topic data message
     * @return  Message empty response
     */
    Message Subscriber::handle(Message msg)
    {
        // verify with the node topic key
        if (!msg.verify(this->topic_keys[msg.getTopic()].getAuthKey())) {

            this->log("could not verify:", msg);

            return Message();
        }

        // AES decrypt and verify hmac with end-to-end topic key
        if (!msg.verifyAndDecrypt(this->topic_keys[msg.getTopic()].getEncKey())) {

            this->log("could not decrypt and verify:", msg);

            return Message();
        }

        this->log("received:", msg);

        return Message();
    }

}
