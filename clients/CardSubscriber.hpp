#pragma once

#include "Subscriber.hpp"
#include "CardClient.hpp"

namespace cdax {

    /**
     * CDAX subscriber class, responsible for receiving and logging topic data
     */
    class CardSubscriber : public Subscriber, public CardClient
    {
    protected:
        Message handle(Message request);

    public:
        CardSubscriber(bytestring identity, std::string port_number, SmartCard *smart_card);
    };

}
