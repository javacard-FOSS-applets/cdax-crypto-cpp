
#include "CardSubscriber.hpp"

namespace cdax {

    /**
     * Construct a new subscriber, given its name,
     * RSA key pair and the port number to listen on
     * @param string identity name of the subscriber
     * @param string port_number port number as string
     * @param string rsa_key_pair
     */
    CardSubscriber::CardSubscriber(bytestring identity, std::string port_number, SmartCard *smart_card)
    {
        this->id = identity;
        this->port = port_number;
        this->card = smart_card;

        // terminal log color
        this->color = GREEN;
    }

    /**
     * Handle topic data messages, verify the two HMACs and decrypt topic data
     * @param   Message msg topic data message
     * @return  Message empty response
     */
    Message CardSubscriber::handle(Message msg)
    {
        if (!msg.decode(card)) {

            this->log("could not decrypt and verify:", msg);

            return Message();
        }

        this->log("received:", msg);

        return Message();
    }

}
