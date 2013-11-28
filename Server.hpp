
#include <boost/unordered_map.hpp>

#include "Common.hpp"
#include "Message.hpp"
#include "Host.hpp"
#include "Client.hpp"

namespace cdax {

    class Node : public Host
    {
    private:
        boost::unordered_map<std::string, CryptoPP::RSA::PublicKey> clients;
        boost::unordered_map<std::string, std::vector<std::string>> subscribers;
        boost::unordered_map<std::string, std::string> sub_ports;
        boost::unordered_map<std::string, CryptoPP::SecByteBlock> topic_keys;
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
