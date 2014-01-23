#pragma once

#include "Publisher.hpp"

namespace cdax {

    /**
     * Publisher is responsible for collecting topic data and sending
     * it to the appropiate node
     */
    class CardPublisher : public Publisher
    {
    public:
        Publisher(bytestring identity, SmartCard *card);

        void publishMessage(bytestring topic, bytestring data);
        void addTopic(bytestring topic_name, std::string topic_port);

    };

}
