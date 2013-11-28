
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

}
