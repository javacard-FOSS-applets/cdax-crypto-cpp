#pragma once

#include <boost/unordered_map.hpp>

#include "../shared/Common.hpp"
#include "../shared/Message.hpp"
#include "../shared/Host.hpp"

#include "../clients/Publisher.hpp"
#include "../clients/Subscriber.hpp"

#include "Node.hpp"

namespace cdax {

    /**
     * The security server class is responsible for initiating clients
     * and nodes and generating their RSA key pairs as wel as topic keys.
     * The server listens for topic join request end sends topic keys to
     * authenticated clients or nodes.
     */
    class SecurityServer : public Host
    {
    private:
        // list of topic names and their key pairs
        boost::unordered_map<std::string, TopicKeyPair> topics;

        // list of node names and public keys
        boost::unordered_map<std::string, CryptoPP::RSA::PublicKey> nodes;

        // list of client names and public keys
        boost::unordered_map<std::string, CryptoPP::RSA::PublicKey> clients;

        // pseudo random number generator
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
