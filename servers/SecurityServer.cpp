
#include "SecurityServer.hpp"

namespace cdax {

    /**
     * Construct a security server and generate a security server RSA key pair
     * @param string identity
     * @param string port_number
     */
    SecurityServer::SecurityServer(bytestring identity, std::string port_number)
    {
        this->id = identity;
        this->port = port_number;
        this->key_pair = this->generateKeyPair(RSAKeyPair::KeyLength);

        // terminal log color
        this->color = RED;
    }

    /**
     * Handle topic join request for clients and nodes
     * The request is verified using the public key of the client or node,
     * but there is no access control in place, for the sake of simplicity and abstraction
     * Cleints receive the full topic key pair, nodes only receive the HMAC
     * or authentication key
     * @param  Message msg request
     * @return Message response
     */
    Message SecurityServer::handle(Message msg)
    {
        // security server only handles topic join requests
        bytestring join = "topic_join";
        if (msg.getData() != join) {

            this->log("received unknown request:", msg);

            return Message();
        }

        // public key of topic key requester
        CryptoPP::RSA::PublicKey *pub_key;

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

        // verify topic request
        if (!msg.verify(pub_key)) {

            this->log("could not verify:", msg);

            return Message();
        }

        // now permissions of the node or lient should be checked

        bytestring data;

        if (this->clients.count(msg.getId())) {

            // encode topic key pair for client
            data = this->topics[msg.getTopic()].getValue();
        } else {

            // encode hmac key for node
            data = *this->topics[msg.getTopic()].getAuthKey();
        }

        Message response(this->id, msg.getTopic(), data);

        // encryopt topic key(s) with client or node public key
        response.encrypt(pub_key);

        // sign with security server private key
        response.sign(this->key_pair.getPrivate());

        this->log("sent topic keys for topic " + msg.getTopic().str() + " to " + msg.getId().str());

        return response;
    }

    /**
     * Generate a AES or HMAC key
     * @param  int length key length
     * @return bytestring the generated key
     */
    bytestring SecurityServer::generateKey(size_t length)
    {
        // Pseudo Random Number Generator
        bytestring key(length);
        prng.GenerateBlock(key, key.size());
        return key;
    }

    /**
     * Generate a new RSA key pair
     * @param  int length key length
     * @return RSAKeyPair
     */
    RSAKeyPair SecurityServer::generateKeyPair(size_t length)
    {
        // Generate Parameters
        CryptoPP::InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(prng, length);

        // return keypair
        RSAKeyPair keyPair(params);
        return keyPair;
    }

    /**
     * Add a new topic and generate the topic keys
     * @param string topic_name name of the topic
     */
    void SecurityServer::addTopic(bytestring topic_name)
    {
        TopicKeyPair topic_key_pair(
            this->generateKey(TopicKeyPair::KeyLength),
            this->generateKey(TopicKeyPair::KeyLength)
        );
        this->topics[topic_name] = topic_key_pair;
    }

    /**
     * Construct a new node, generate a keypairt and set the required attributes
     * @param  string node_name name of the node
     * @param  string port the port number of the node
     * @return Node
     */
    Node* SecurityServer::addNode(bytestring node_name, std::string port)
    {
        RSAKeyPair rsa_key_pair = this->generateKeyPair(RSAKeyPair::KeyLength);
        this->nodes[node_name] = rsa_key_pair.getPublic();
        Node *node = new Node(node_name, port, rsa_key_pair);
        node->setClients(clients);
        node->setServer(this->getPort(), this->key_pair.getPublic());

        return node;
    }

    /**
     * Construct a new subscriber, generate a keypairt and set the required attributes
     * @param  string node_name name of the subscriber
     * @param  string port the port number of the subscriber
     * @return Subscriber
     */
    Subscriber* SecurityServer::addSubscriber(bytestring client_name, std::string port)
    {
        RSAKeyPair rsa_key_pair = this->generateKeyPair(RSAKeyPair::KeyLength);
        this->clients[client_name] = rsa_key_pair.getPublic();
        Subscriber *sub = new Subscriber(client_name, port, rsa_key_pair);
        sub->setServer(this->key_pair.getPublic());

        return sub;
    }

    /**
     * Construct a new publisher, generate a keypair and set the required attributes
     * @param  string node_name name of the publisher
     * @return Publisher
     */
    Publisher* SecurityServer::addPublisher(bytestring client_name)
    {
        RSAKeyPair rsa_key_pair = this->generateKeyPair(RSAKeyPair::KeyLength);
        this->clients[client_name] = rsa_key_pair.getPublic();
        Publisher *pub = new Publisher(client_name, rsa_key_pair);
        pub->setServer(this->key_pair.getPublic());

        return pub;
    }

    /**
     * Construct a new publisher, generate a keypairt on a smart card and set the required attributes
     * @param  string node_name name of the publisher
     * @return Publisher
     */
    Publisher* SecurityServer::addPublisher(bytestring client_name, SmartCard *card)
    {
        if (!card->connect()) {
            throw new CardException("Card not found");
        }

        RSAKeyPair rsa_key_pair = this->generateKeyPair(RSAKeyPair::KeyLength);
        this->clients[client_name] = rsa_key_pair.getPublic();
        Publisher *pub = new Publisher(client_name, rsa_key_pair);
        pub->setServer(this->key_pair.getPublic());

        return pub;
    }
}


