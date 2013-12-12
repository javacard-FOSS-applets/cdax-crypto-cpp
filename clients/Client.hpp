#pragma once

#include <boost/unordered_map.hpp>

#include "../shared/Host.hpp"
#include "../card/SmartCard.hpp"

namespace cdax {

    /**
     * Abtract CDAX client. This class is responsible for requesting
     * a topic key from the security server
     */
    class Client : public Host
    {
    protected:
        // list of topic names
        std::vector<std::string> topics;

        // list of topic key pairs per topic name
        boost::unordered_map<std::string, TopicKeyPair> topic_keys;

        // list of node ports per topic name
        boost::unordered_map<std::string, std::string> topic_ports;

        // smart card
        SmartCard *card = NULL;

    public:
        void addTopic(std::string topic_name, std::string topic_port);
        void setServer(CryptoPP::RSA::PublicKey key);
    };

}
