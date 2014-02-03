
#include "CardPublisher.hpp"

namespace cdax {

    CardPublisher::CardPublisher(bytestring identity, SmartCard *smart_card)
    {
        this->id = identity;
        this->card = smart_card;

        // terminal log color
        this->color = BLUE;
    }

    void CardPublisher::publishMessage(bytestring topic, bytestring data)
    {
        // create random topic data message
        Message msg(this->id, topic, data);

        // hmac and AES encrypt with end-to-end topic key
        msg.encode(card);

        this->log("published:", msg);

        send(msg, this->topic_ports[topic]);
    }

}
