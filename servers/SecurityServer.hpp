#pragma once

#include <boost/unordered_map.hpp>

#include "../shared/Common.hpp"
#include "../shared/Message.hpp"
#include "../shared/Host.hpp"

#include "../clients/Publisher.hpp"
#include "../clients/Subscriber.hpp"

#include "Node.hpp"

namespace cdax {

    class SecurityServer : public Host
    {
    private:
        boost::unordered_map<std::string, TopicKeyPair> topics;
        boost::unordered_map<std::string, CryptoPP::RSA::PublicKey> nodes;
        boost::unordered_map<std::string, CryptoPP::RSA::PublicKey> clients;

        CryptoPP::AutoSeededRandomPool prng;

        CryptoPP::SecByteBlock generateKey(size_t length);
        RSAKeyPair generateKeyPair(size_t length);

    protected:
        Message handle(Message msg);

    public:
        SecurityServer(std::string identity, std::string port_number);

        void addTopic(std::string topic_name);
        Node addNode(std::string node_name, std::string port);
        Publisher addPublisher(std::string client_name);
        Subscriber addSubscriber(std::string client_name, std::string port);


    };

};
