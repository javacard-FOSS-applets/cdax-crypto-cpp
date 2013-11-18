
#include <boost/lexical_cast.hpp>

#include "Message.hpp"
#include "Network.hpp"
#include "Client.hpp"
#include "Server.hpp"

using namespace cdax;

int main(int argc, char* argv[])
{
    RSAKeyPair s0_kp = generateKeyPair(1024);
    RSAKeyPair s1_kp = generateKeyPair(1024);
    RSAKeyPair p0_kp = generateKeyPair(1024);

    SecurityServer *s = new SecurityServer("sec_server", "7000");
    Node *n0 = new Node("node_o", "6000", s->getPort());
    Subscriber *s0 = new Subscriber("subscriber_0", "5000", s0_kp);
    Subscriber *s1 = new Subscriber("subscriber_1", "5001", s1_kp);
    Publisher *p0 = new Publisher("publisher_0", p0_kp);

    TopicKeyPair *kp;
    std::string topic_name;

    s->addClient(s0->getId(), s0_kp.getPublic());
    s->addClient(s1->getId(), s1_kp.getPublic());
    s->addClient(p0->getId(), p0_kp.getPublic());

    boost::thread_group thrds;
    thrds.create_thread(std::bind(&SecurityServer::serve, s));
    thrds.create_thread(std::bind(&Node::serve, n0));

    for (int i = 0; i < 4; ++i) {
        kp = new TopicKeyPair(16, CryptoPP::AES::DEFAULT_KEYLENGTH);
        topic_name = "topic_" + boost::lexical_cast<std::string>(i);

        s->addTopic(topic_name, *kp);
        n0->addTopic(topic_name, kp->getAuthKey());

        n0->addSubscriber(topic_name, s0->getId(), s0->getPort());
        s0->addTopic(topic_name, n0->getPort());

        if (i > 1) {
            n0->addSubscriber(topic_name, s1->getId(), s1->getPort());
            s1->addTopic(topic_name, n0->getPort());
        }

        p0->setCipher(Cipher::AES_GCM);
        p0->addTopic(topic_name, n0->getPort());
    }

    thrds.create_thread(std::bind(&Subscriber::serve, s0));
    thrds.create_thread(std::bind(&Subscriber::serve, s1));
    thrds.create_thread(std::bind(&Publisher::generateRandom, p0));

    thrds.join_all();

    return 0;
}
