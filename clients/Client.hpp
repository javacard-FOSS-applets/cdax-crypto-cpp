#pragma once

#include <boost/unordered_map.hpp>

#include "../shared/Host.hpp"

namespace cdax {

    class Client : public Host
    {
    protected:
        std::vector<std::string> topics;
        boost::unordered_map<std::string, TopicKeyPair> topic_keys;
        boost::unordered_map<std::string, std::string> topic_ports;

    public:
        void addTopic(std::string topic_name, std::string topic_port);
        void setServer(CryptoPP::RSA::PublicKey key);
    };

}
