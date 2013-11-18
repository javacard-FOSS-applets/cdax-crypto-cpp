
#include <boost/unordered_map.hpp>

#include "Message.hpp"
#include "Network.hpp"

namespace cdax {

    class Node : public Network
    {
    private:
        boost::unordered_map<std::string, std::vector<std::string>> subscribers;
        boost::unordered_map<std::string, std::string> sub_ports;
        boost::unordered_map<std::string, CryptoPP::SecByteBlock> topic_keys;
        std::string sec_server_port;

    protected:
        Message handle(Message msg);

    public:
        Node(std::string identity, std::string port_number, std::string server_port);
        void addTopic(std::string topic_name, CryptoPP::SecByteBlock auth_key);
        void addSubscriber(std::string topic_name, std::string sub_name, std::string sub_port);

    };

    class SecurityServer : public Network
    {
    private:
        boost::unordered_map<std::string, TopicKeyPair> topic_keys;
        boost::unordered_map<std::string, CryptoPP::RSA::PublicKey> client_public_keys;

    protected:
        Message handle(Message msg);

    public:
        SecurityServer(std::string identity, std::string port_number);
        void addTopic(std::string topic_name, TopicKeyPair topic_key_pair);
        void addClient(std::string client_name, CryptoPP::RSA::PublicKey public_key);
    };

};
