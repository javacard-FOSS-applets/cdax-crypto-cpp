
#include "Client.hpp"

namespace cdax {

    void Client::addTopic(std::string topic_name, std::string port_number)
    {
        this->topics.push_back(topic_name);
        this->topic_ports[topic_name] = port_number;

        // wait one second before requesting topic keys
        usleep(1000000);

        Message request;
        request.setId(this->id);
        request.setTopic(topic_name);
        request.setData("topic_join");
        request.sign(this->key_pair.getPrivate());

        this->log("sent topic join request for" + topic_name, request);

        Message response = send(request, port_number);

        response.decrypt(this->key_pair.getPrivate());

        TopicKeyPair *kp = new TopicKeyPair(response.getData());
        this->topic_keys[topic_name] = *kp;
    }

    std::string Client::getId()
    {
        return this->id;
    }

    Publisher::Publisher(std::string identity, RSAKeyPair kp)
    {
        this->id = identity;
        this->key_pair = kp;

        this->color = BLUE;
    }

    void Publisher::setCipher(Cipher::CipherType c)
    {
        this->cipher = c;
    }

    void Publisher::generateRandom()
    {
        Message msg;
        std::string random_topic;

        for (;;)
        {
            // wait one second before sending the next message
            usleep(1000000);

            random_topic = this->topics[rand() % this->topics.size()];

            msg.setId(this->id);
            msg.setTopic(random_topic);
            msg.setData(randomString(8));
            msg.setCipher(this->cipher);

            this->log("published:", msg);

            msg.encrypt(this->topic_keys[random_topic].getEncKey());
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
        msg.decrypt(this->topic_keys[msg.getTopic()].getEncKey());

        this->log("received:", msg);

        return Message();
    }

}
