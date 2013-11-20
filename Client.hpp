#pragma once

#include <boost/unordered_map.hpp>

#include "Message.hpp"
#include "Host.hpp"

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

    class Publisher : public Client
    {
    private:
        Cipher::CipherType cipher;

    public:
        Publisher(std::string identity, RSAKeyPair kp);
        void setCipher(Cipher::CipherType c);
        void generateRandom();
    };

    class Subscriber : public Client
    {
    protected:
        Message handle(Message request);

    public:
        Subscriber(std::string identity, std::string port_number, RSAKeyPair kp);
    };

}
