
#include "Publisher.hpp"

namespace cdax {

    /**
     * Construct a new publisher, given a name and RSA key pair
     * @param string identity
     * @param RSAKeyPair rsa_key_pair
     */
    Publisher::Publisher(std::string identity, RSAKeyPair rsa_key_pair)
    {
        this->id = identity;
        this->key_pair = rsa_key_pair;

        // terminal log color
        this->color = BLUE;

        // connect to private smart card
        this->card = new SmartCard();

        this->log("is connecting to smart card...");

        if (!card->selectReader()) {
            this->log(card->getError());
            return;
        }

        if (!card->waitForCard()) {
            this->log(card->getError());
            return;
        }

        if (!card->storePrivateKey(this->key_pair.getPrivate())) {
            this->log(card->getError());
            return;
        }
    }

    void Publisher::publishMessage(std::string topic, std::string data)
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

    /**
     * Generate random topic data and send the message to the appropriate node
     */
    void Publisher::generateRandom()
    {
        // loop endlessly
        for (;;)
        {
            // wait random time before sending the next message
            this->sleep();

            // do nothing if there are no topic keys present
            if (this->topics.size() == 0) {
                continue;
            }

            std::string random_topic = this->topics[rand() % this->topics.size()];
            std::string random_data = randomString(8);

            this->publishMessage(random_topic, random_data);
        }
    }

}
