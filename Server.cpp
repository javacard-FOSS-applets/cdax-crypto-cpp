
#include "Server.hpp"

namespace cdax {

    Node::Node(std::string identity, std::string port_number, RSAKeyPair kp)
    {
        this->id = identity;
        this->port = port_number;
        this->key_pair = kp;

        this->color = MAGENTA;
    }

    void Node::addTopic(std::string topic_name)
    {
        Message request;
        request.setId(this->id);
        request.setTopic(topic_name);
        request.setData("topic_join");
        request.sign(this->key_pair.getPrivate());

        this->log("sent topic join request for " + topic_name);

        Message response = send(request, this->sec_server_port);

        response.decrypt(this->key_pair.getPrivate());
        response.verify(this->sec_server_key);

        TopicKeyPair *kp = new TopicKeyPair(response.getData());
        this->topic_keys[topic_name] = kp->getAuthKey();
    }

    void Node::setClients(boost::unordered_map<std::string, CryptoPP::RSA::PublicKey> clnts)
    {
        this->clients = clnts;
    }

    void Node::setServer(std::string port, CryptoPP::RSA::PublicKey key)
    {
        this->sec_server_port = port;
        this->sec_server_key = key;
    }

    void Node::addSubscriber(std::string topic_name, std::string sub_name, std::string sub_port)
    {
        this->subscribers[topic_name].push_back(sub_name);
        this->sub_ports[sub_name] = sub_port;
    }

    Message Node::handle(Message msg)
    {
        if (msg.getData().compare("topic_join") == 0) {

            // verify topic join request
            msg.verify(this->clients[msg.getId()]);

            // load topic keys if they are not present
            if (this->topic_keys.count(msg.getTopic()) == 0) {
                this->addTopic(msg.getTopic());
            }

            this->log("forwarded topic join request of " + msg.getId());

            return send(msg, this->sec_server_port);
        }

        if (subscribers.count(msg.getTopic()) == 0) {
            return Message();
        }

        if (topic_keys.count(msg.getTopic()) == 0) {
            return Message();
        }

        // verify topic data HMAC
        msg.verify(this->topic_keys[msg.getTopic()]);

        // load list of subscribers
        std::vector<std::string> subs = subscribers[msg.getTopic()];

        this->log("forwarded to " + boost::lexical_cast<std::string>(subs.size()) + " subscribers");

        // forward message
        for (std::vector<std::string>::size_type i = 0; i < subs.size(); ++i) {
            send(msg, this->sub_ports[subs[i]]);
        }

        return Message();
    }

    SecurityServer::SecurityServer(std::string identity, std::string port_number)
    {
        this->id = identity;
        this->port = port_number;
        this->key_pair = this->generateKeyPair(1024);

        this->color = RED;
    }

    Message SecurityServer::handle(Message msg)
    {
        if (msg.getData().compare("topic_join") != 0) {
            return Message();
        }

        CryptoPP::RSA::PublicKey pub_key;

        if (this->clients.count(msg.getId())) {
            pub_key = this->clients[msg.getId()];
        } else if (this->nodes.count(msg.getId())) {
            pub_key = this->nodes[msg.getId()];
        } else {
            return Message();
        }

        msg.verify(pub_key);

        TopicKeyPair topic_keys = this->topics[msg.getTopic()];

        Message response;
        response.setId(this->id);
        response.setTopic(msg.getTopic());
        response.setData(topic_keys.toString());

        response.sign(this->key_pair.getPrivate());

        response.encrypt(pub_key);

        this->log("sent topic keys for topic " + msg.getTopic() + " to " + msg.getId());

        return response;
    }

    CryptoPP::SecByteBlock SecurityServer::generateKey(size_t length)
    {
        // Pseudo Random Number Generator
        CryptoPP::SecByteBlock key(length);
        prng.GenerateBlock(key, key.size());
        return key;
    }

    RSAKeyPair SecurityServer::generateKeyPair(size_t length)
    {
        // Generate Parameters
        CryptoPP::InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(prng, length);
        // return keypair
        RSAKeyPair keyPair(params);
        return keyPair;
    }

    void SecurityServer::addTopic(std::string topic_name)
    {
        TopicKeyPair kp(this->generateKey(16), this->generateKey(16));
        this->topics[topic_name] = kp;
    }

    Node SecurityServer::addNode(std::string node_name, std::string port)
    {
        RSAKeyPair kp = this->generateKeyPair(1024);
        this->nodes[node_name] = kp.getPublic();
        Node n(node_name, port, kp);
        n.setClients(clients);
        n.setServer(this->getPort(), this->key_pair.getPublic());

        return n;
    }

    Subscriber SecurityServer::addSubscriber(std::string client_name, std::string port)
    {
        RSAKeyPair kp = this->generateKeyPair(1024);
        this->clients[client_name] = kp.getPublic();
        Subscriber s(client_name, port, kp);
        s.setServer(this->key_pair.getPublic());

        return s;
    }

    Publisher SecurityServer::addPublisher(std::string client_name)
    {
        RSAKeyPair kp = this->generateKeyPair(1024);
        this->clients[client_name] = kp.getPublic();
        Publisher p(client_name, kp);
        p.setServer(this->key_pair.getPublic());

        return p;
    }

}


