
#include "Node.hpp"

namespace cdax {

    /**
     * Construct a new node intsance given a identity string,
     * port numer and RSA key pair
     * @param string identity
     * @param string port_number
     * @param string rsa_key_pair
     */
    Node::Node(bytestring identity, std::string port_number, RSAKeyPair rsa_key_pair)
    {
        this->id = identity;
        this->port = port_number;
        this->key_pair = rsa_key_pair;

        // terminal log color
        this->color = MAGENTA;
    }

    /**
     * Add a topic to the list of topics this Node is responsible for
     * Requests a topic key from the security server
     * @param string topic_name
     */
    void Node::addTopic(bytestring topic_name)
    {
        // create topic join request Message
        Message request(this->id, topic_name, "topic_join");

        // sign request with private key
        request.sign(this->key_pair.getPrivate());

        this->log("sent topic join request for " + topic_name.str());

        Message response = send(request, this->sec_server_port);

        // verify topic key message
        if (!response.verify(this->sec_server_key)) {

            this->log("could not verify:", response);

            return;
        }

        // decrypt Message with private key
        if (!response.decrypt(this->key_pair.getPrivate())) {

            this->log("could not decrypt:", response);

            return;
        }

        // store topic key
        this->topic_keys[topic_name] = response.getData();
    }

    /**
     * Set the list of clients and their respective public keys
     * @param client_keys
     */
    void Node::setClients(boost::unordered_map<bytestring, CryptoPP::RSA::PublicKey*> client_keys)
    {
        this->clients = client_keys;
    }

    /**
     * Define the port number and public key of the security server
     * @param string port
     * @param string server_public_key
     */
    void Node::setServer(std::string port, CryptoPP::RSA::PublicKey *server_public_key)
    {
        this->sec_server_port = port;
        this->sec_server_key = server_public_key;
    }

    /**
     * Add a subscriber to the list of subscribers per topic name
     * @param string topic_name topic name
     * @param string sub_name subscriber name
     * @param string sub_port subscriber port number
     */
    void Node::addSubscriber(bytestring topic_name, bytestring sub_name, std::string sub_port)
    {
        this->subscribers[topic_name].push_back(sub_name);
        this->sub_ports[sub_name] = sub_port;
    }

    /**
     * Handle a new message
     * A message could be simple topic data that needs to be
     * authenticated and forwarden to the appropriate subscribers
     * or a topic join request that needs to be formwarden to the
     * security server
     * @param  Message msg request
     * @return Message response
     */
    Message Node::handle(Message msg)
    {
        bytestring join = "topic_join";
        if (msg.getData() == join) {

            // verify topic join request
            if (!msg.verify(this->clients[msg.getId()])) {

                this->log("could not verify:", msg);

                return Message();
            }

            // load topic keys if they are not present
            if (this->topic_keys.count(msg.getTopic()) == 0) {
                this->addTopic(msg.getTopic());
            }

            this->log("forwarded topic join request of " + msg.getId().str());

            Message response = send(msg, this->sec_server_port);

            // verify response from the security server
            if (!response.verify(this->sec_server_key)) {

                this->log("could not verify:", response);

                return Message();
            }

            return response;
        }

        // check for topic subscribers
        if (subscribers.count(msg.getTopic()) == 0) {
            return Message();
        }

        // check for topic key
        if (topic_keys.count(msg.getTopic()) == 0) {

            // load topic keys if they are not present
            if (this->topic_keys.count(msg.getTopic()) == 0) {
                this->addTopic(msg.getTopic());
            }

            if (topic_keys.count(msg.getTopic()) == 0) {

                this->log("could not obtian topic key for " + msg.getTopic().str());

                return Message();
            }
        }

        // verify topic data HMAC
        if (!msg.hmacVerify(&this->topic_keys[msg.getTopic()])) {

            this->log("could not verify:", msg);

            return Message();
        }

        // load list of subscribers
        std::vector<bytestring> subs = subscribers[msg.getTopic()];

        this->log("forwarded to " + boost::lexical_cast<std::string>(subs.size()) + " subscribers");

        // forward message
        for (std::vector<bytestring>::size_type i = 0; i < subs.size(); ++i) {
            send(msg, this->sub_ports[subs[i]]);
        }

        return Message();
    }

}
