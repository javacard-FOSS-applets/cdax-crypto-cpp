
#include "CardPublisher.hpp"

namespace cdax {

    CardPublisher::CardPublisher(bytestring identity, SmartCard *card)
    {
        this->id = identity;

        // terminal log color
        this->color = BLUE;
    }

    /**
     * Add a topic name and request its corresponding topic keys from the security server
     * @param string topic_name
     * @param string port_number port number of the node
     */
    void Client::addTopic(bytestring topic_name, std::string port_number)
    {
        this->topics.push_back(topic_name);
        this->topic_ports[topic_name] = port_number;

        // create topic join request
        Message request(this->id, topic_name, "topic_join");

        // sign with private key
        request.sign(this->key_pair.getPrivate());

        if (this->card != NULL) {

            this->log("signed on device:", request);

            request.signOnCard(this->card);

            this->log("signed on card:", request);
        }

        this->log("sent topic join request for " + topic_name.str());

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

        if (response.getData().size() == 0) {

            this->log("received an empty topic join response for " + topic_name.str());

            return;
        }

        this->log("received topic keys for " + topic_name.str());

        // store the topic keypair
        TopicKeyPair topic_key_pair(response.getData());
        this->topic_keys[topic_name] = topic_key_pair;
    }


    void CardPublisher::publishMessage(bytestring topic, bytestring data)
    {
        // create random topic data message
        Message msg(this->id, topic, data);

        this->log("published:", msg);

        // hmac and AES encrypt with end-to-end topic key
        msg.encryptAndHMAC(this->topic_keys[topic].getEncKey());

        // hmac with node topic key
        msg.hmac(this->topic_keys[topic].getAuthKey());

        send(msg, this->topic_ports[topic]);
    }

}
