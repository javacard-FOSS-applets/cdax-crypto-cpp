
#include "Client.hpp"

namespace cdax {

    /**
     * Add a topic name and request its corresponding topic keys from the security server
     * @param string topic_name
     * @param string port_number port number of the node
     */
    void Client::addTopic(std::string topic_name, std::string port_number)
    {
        this->topics.push_back(topic_name);
        this->topic_ports[topic_name] = port_number;

        // create topic join request
        Message request(this->id, topic_name, "topic_join");

        // sign with private key
        request.sign(this->key_pair.getPrivate());

        this->log("sent topic join request for " + topic_name);

        Message response = send(request, port_number);

        // verify response with security server public key
        if (!response.verify(this->sec_server_key)) {

            this->log("could not verify:", response);

            return;
        }

        // decrypt with private key
        if (!response.decrypt(this->key_pair.getPrivate())) {

            this->log("could not decrypt:", response);

            return;
        }

        this->log("received topic keys for " + topic_name);

        // store the topic keypair
        TopicKeyPair topic_key_pair(response.getData());
        this->topic_keys[topic_name] = topic_key_pair;
    }

    /**
     * Set security server public key to verify topic join reponses
     * @param CryptoPP::RSA::PublicKey key security server public key
     */
    void Client::setServer(CryptoPP::RSA::PublicKey key)
    {
        this->sec_server_key = key;
    }

}
