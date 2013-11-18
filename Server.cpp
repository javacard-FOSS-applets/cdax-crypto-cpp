
#include "Server.hpp"

namespace cdax {

    Node::Node(std::string identity, std::string port_number, std::string server_port)
    {
        this->id = identity;
        this->port = port_number;
        this->sec_server_port = server_port;

        this->color = MAGENTA;
    }

    void Node::addTopic(std::string topic_name, CryptoPP::SecByteBlock auth_key)
    {
        this->topic_keys[topic_name] = auth_key;
    }

    void Node::addSubscriber(std::string topic_name, std::string sub_name, std::string sub_port)
    {
        this->subscribers[topic_name].push_back(sub_name);
        this->sub_ports[sub_name] = sub_port;
    }

    Message Node::handle(Message msg)
    {
        if (msg.getData().compare("topic_join") == 0) {
            return send(msg, this->sec_server_port);
        }

        std::vector<std::string> subs = subscribers[msg.getTopic()];
        msg.verify(this->topic_keys[msg.getTopic()]);

        this->log("forwarded to " + boost::lexical_cast<std::string>(subs.size()) + " subscribers:", msg);

        for (std::vector<std::string>::size_type i = 0; i < subs.size(); ++i) {
            // forward messages
            send(msg, this->sub_ports[subs[i]]);
        }

        return Message();
    }

    SecurityServer::SecurityServer(std::string identity, std::string port_number)
    {
        this->id = identity;
        this->port = port_number;

        this->color = RED;
    }

    void SecurityServer::addTopic(std::string topic_name, TopicKeyPair topic_key_pair)
    {
        this->topic_keys[topic_name] = topic_key_pair;
    }

    void SecurityServer::addClient(std::string client_name, CryptoPP::RSA::PublicKey public_key)
    {
        this->client_public_keys[client_name] = public_key;
    }

    Message SecurityServer::handle(Message msg)
    {
        if (msg.getData().compare("topic_join") != 0) {
            return Message();
        }

        msg.verify(this->client_public_keys[msg.getId()]);
        TopicKeyPair kp = this->topic_keys[msg.getTopic()];

        Message response;
        response.setId(this->id);
        response.setTopic(msg.getTopic());
        response.setData(kp.toString());

        response.encrypt(this->client_public_keys[msg.getId()]);

        this->log("sent topic keys to " + msg.getId(), response);

        return response;
    }

}


