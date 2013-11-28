
#include "Server.hpp"

namespace cdax {

    Node::Node(std::string identity, std::string port_number, RSAKeyPair rsa_key_pair)
    {
        this->id = identity;
        this->port = port_number;
        this->key_pair = rsa_key_pair;

        // terminal log color
        this->color = MAGENTA;
    }

    void Node::addTopic(std::string topic_name)
    {
        // create topic join request Message
        Message request(this->id, topic_name, "topic_join");

        // sign request with private key
        request.sign(this->key_pair.getPrivate());

        this->log("sent topic join request for " + topic_name);

        Message response = send(request, this->sec_server_port);

        // verify topic key message
        response.verify(this->sec_server_key);

        // decrypt Message with private key
        response.decrypt(this->key_pair.getPrivate());

        // store topic key
        this->topic_keys[topic_name] = stringToSec(response.getData());
    }

    void Node::setClients(boost::unordered_map<std::string, CryptoPP::RSA::PublicKey> client_keys)
    {
        this->clients = client_keys;
    }

    void Node::setServer(std::string port, CryptoPP::RSA::PublicKey server_public_key)
    {
        this->sec_server_port = port;
        this->sec_server_key = server_public_key;
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

            Message response = send(msg, this->sec_server_port);

            // verify response from the security server
            response.verify(this->sec_server_key);

            return response;
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
        this->key_pair = this->generateKeyPair(RSAKeyPair::KeyLength);

        // terminal log color
        this->color = RED;
    }

    Message SecurityServer::handle(Message msg)
    {
        // security server only handles topic join requests
        if (msg.getData().compare("topic_join") != 0) {
            return Message();
        }

        // public key of topic key requester
        CryptoPP::RSA::PublicKey pub_key;

        // select the public key of a client or node
        if (this->clients.count(msg.getId())) {

            // get client public key
            pub_key = this->clients[msg.getId()];
        } else if (this->nodes.count(msg.getId())) {

            // GET NODE PUBLIC KEY
            pub_key = this->nodes[msg.getId()];
        } else {

            // if client or node is unknown, ignore rquest
            return Message();
        }

        // vereify topic request
        msg.verify(pub_key);

        // now permissions of the node or lient should be checked

        std::string data;

        if (this->clients.count(msg.getId())) {

            // encode topic key pair for client
            data = this->topics[msg.getTopic()].toString();
        } else {

            // encode hmac key for node
            data = secToString(this->topics[msg.getTopic()].getAuthKey());
        }

        Message response(this->id, msg.getTopic(), data);

        // encryopt topic key(s) with client or node public key
        response.encrypt(pub_key);

        // sign with security server private key
        response.sign(this->key_pair.getPrivate());

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
        TopicKeyPair topic_key_pair(
            this->generateKey(TopicKeyPair::KeyLength),
            this->generateKey(TopicKeyPair::KeyLength)
        );
        this->topics[topic_name] = topic_key_pair;
    }

    Node SecurityServer::addNode(std::string node_name, std::string port)
    {
        RSAKeyPair rsa_key_pair = this->generateKeyPair(RSAKeyPair::KeyLength);
        this->nodes[node_name] = rsa_key_pair.getPublic();
        Node node(node_name, port, rsa_key_pair);
        node.setClients(clients);
        node.setServer(this->getPort(), this->key_pair.getPublic());

        return node;
    }

    Subscriber SecurityServer::addSubscriber(std::string client_name, std::string port)
    {
        RSAKeyPair rsa_key_pair = this->generateKeyPair(RSAKeyPair::KeyLength);
        this->clients[client_name] = rsa_key_pair.getPublic();
        Subscriber sub(client_name, port, rsa_key_pair);
        sub.setServer(this->key_pair.getPublic());

        return sub;
    }

    Publisher SecurityServer::addPublisher(std::string client_name)
    {
        RSAKeyPair rsa_key_pair = this->generateKeyPair(RSAKeyPair::KeyLength);
        this->clients[client_name] = rsa_key_pair.getPublic();
        Publisher pub(client_name, rsa_key_pair);
        pub.setServer(this->key_pair.getPublic());

        return pub;
    }

}


