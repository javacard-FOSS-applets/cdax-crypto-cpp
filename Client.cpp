
#include "Client.hpp"

namespace cdax {

    void Client::addTopic(std::string topic_name, std::string port_number)
    {
        this->topics.push_back(topic_name);
        this->topic_ports[topic_name] = port_number;

        Message request;
        request.setId(this->id);
        request.setTopic(topic_name);
        request.setData("topic_join");

        request.sign(this->key_pair.getPrivate());

        this->log("sent topic join request for " + topic_name);

        Message response = send(request, port_number);

        response.decrypt(this->key_pair.getPrivate());
        response.verify(this->sec_server_key);

        this->log("received topic keys for " + topic_name);

        TopicKeyPair kp(response.getData());
        this->topic_keys[topic_name] = kp;
    }

    void Client::setServer(CryptoPP::RSA::PublicKey key)
    {
        this->sec_server_key = key;
    }

    Publisher::Publisher(std::string identity, RSAKeyPair kp)
    {
        this->id = identity;
        this->key_pair = kp;

        this->color = BLUE;
    }

    void Publisher::generateRandom()
    {
        for (;;)
        {
            // wait random time before sending the next message
            this->sleep();

            if (this->topics.size() == 0) {
                continue;
            }

            std::string random_topic = this->topics[rand() % this->topics.size()];

            Message msg;

            msg.setId(this->id);
            msg.setTopic(random_topic);
            msg.setData(randomString(8));

            this->log("published:", msg);

            msg.signEncrypt(this->topic_keys[random_topic].getEncKey());
            msg.sign(this->topic_keys[random_topic].getAuthKey());

            send(msg, this->topic_ports[random_topic]);
        }
    }

    Subscriber::Subscriber(std::string identity, std::string port_number, RSAKeyPair kp)
    {
        this->id = identity;
        this->port = port_number;
        this->key_pair = kp;

        this->color = GREEN;
    }

    Message Subscriber::handle(Message msg)
    {
        msg.verify(this->topic_keys[msg.getTopic()].getAuthKey());
        msg.verifyDecrypt(this->topic_keys[msg.getTopic()].getEncKey());

        this->log("received:", msg);

        return Message();
    }

}
