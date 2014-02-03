
#include "CardClient.hpp"

namespace cdax {


    CryptoPP::RSA::PublicKey CardClient::initKeys(CryptoPP::RSA::PublicKey server_key)
    {
        CryptoPP::RSA::PublicKey pub;
        this->sec_server_key = server_key;

        if (file_exists("data/client-pub.key")) {
            pub = RSAKeyPair::loadPubKey("data/client-pub.key");
        } else {
            pub = card->initialize(this->sec_server_key);
            RSAKeyPair::saveKey("data/client-pub.key", pub);
        }

        this->key_pair = RSAKeyPair();
        this->key_pair.setPublic(pub);

        return pub;
    }

    /**
     * Add a topic name and request its corresponding topic keys from the security server
     * @param string topic_name
     * @param string port_number port number of the node
     */
    void CardClient::addTopic(bytestring topic_name, std::string port_number)
    {
        this->topics.push_back(topic_name);
        this->topic_ports[topic_name] = port_number;

        // create topic join request
        Message request(this->id, topic_name, "topic_join");

        request.sign(this->card);

        this->log("sent topic join request for (signed on card) " + topic_name.str());

        Message response = send(request, port_number);

        if (!response.handleTopicKeyResponse(card)) {

            this->log("could not store topic keys for " + topic_name.str());

            return;
        }

        this->log("received topic keys for " + topic_name.str());
    }


}
