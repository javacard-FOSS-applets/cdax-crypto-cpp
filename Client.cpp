
#include "Client.hpp"

namespace cdax {

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
        response.verify(this->sec_server_key);

        // decrypt with private key
        response.decrypt(this->key_pair.getPrivate());

        this->log("received topic keys for " + topic_name);

        // store the topic keypair
        TopicKeyPair topic_key_pair(response.getData());
        this->topic_keys[topic_name] = topic_key_pair;
    }

    void Client::setServer(CryptoPP::RSA::PublicKey key)
    {
        this->sec_server_key = key;
    }

    Publisher::Publisher(std::string identity, RSAKeyPair rsa_key_pair)
    {
        this->id = identity;
        this->key_pair = rsa_key_pair;

        // terminal log color
        this->color = BLUE;
    }

    void Publisher::generateRandom()
    {
        for (;;)
        {
            // wait random time before sending the next message
            this->sleep();

            // do nothing if there are no topic keys present
            if (this->topics.size() == 0) {
                continue;
            }

            std::string random_topic = this->topics[rand() % this->topics.size()];

            // create random topic data message
            Message msg(this->id, random_topic, randomString(8));

            this->log("published:", msg);

            // hmac and AES encrypt with end-to-end topic key
            msg.hmacAndEncrypt(this->topic_keys[random_topic].getEncKey());

            // hmac with node topic key
            msg.hmac(this->topic_keys[random_topic].getAuthKey());

            send(msg, this->topic_ports[random_topic]);
        }
    }

    Subscriber::Subscriber(std::string identity, std::string port_number, RSAKeyPair rsa_key_pair)
    {
        this->id = identity;
        this->port = port_number;
        this->key_pair = rsa_key_pair;

        // terminal log color
        this->color = GREEN;
    }

    Message Subscriber::handle(Message msg)
    {
        // verify with the node topic key
        msg.verify(this->topic_keys[msg.getTopic()].getAuthKey());

        // AES decrypt and verify hmac with end-to-end topic key
        msg.decryptAndVerify(this->topic_keys[msg.getTopic()].getEncKey());

        this->log("received:", msg);

        return Message();
    }

}
