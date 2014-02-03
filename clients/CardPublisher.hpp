#pragma once

#include "Publisher.hpp"
#include "CardClient.hpp"

namespace cdax {

    /**
     * Publisher is responsible for collecting topic data and sending
     * it to the appropiate node
     */
    class CardPublisher : public Publisher, public CardClient
    {
    public:
        CardPublisher(bytestring identity, SmartCard *smart_card);

        void publishMessage(bytestring topic, bytestring data);

    };

}
