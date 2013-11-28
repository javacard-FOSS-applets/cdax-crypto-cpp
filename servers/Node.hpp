#pragma once

#include <boost/unordered_map.hpp>

#include "../shared/Common.hpp"
#include "../shared/Message.hpp"
#include "../shared/Host.hpp"

namespace cdax {

    /**
     * The Node class implement a CDAX Designated Node
     * It is responsible for formwarding topic data and topic join requests
     * while authenticating *all* traffic
     */
    class Node : public Host
    {
    private:
        // list of client public keys
        boost::unordered_map<std::string, CryptoPP::RSA::PublicKey> clients;

        // list of subscriber identities per topic name
        boost::unordered_map<std::string, std::vector<std::string>> subscribers;

        // list of port numbers per subscriber name
        boost::unordered_map<std::string, std::string> sub_ports;

        // list of topic keys per topic name
        boost::unordered_map<std::string, CryptoPP::SecByteBlock> topic_keys;

        // port number of the security server
        std::string sec_server_port;

    protected:
        Message handle(Message msg);

    public:
        Node(std::string identity, std::string port_number, RSAKeyPair rsa_key_pair);

        void addTopic(std::string topic_name);
        void addSubscriber(std::string topic_name, std::string sub_name, std::string sub_port);

        void setClients(boost::unordered_map<std::string, CryptoPP::RSA::PublicKey> client_keys);
        void setServer(std::string port, CryptoPP::RSA::PublicKey server_public_key);

    };

};
