
#include <boost/lexical_cast.hpp>

#include "Message.hpp"
#include "Host.hpp"
#include "Client.hpp"
#include "Server.hpp"

using namespace cdax;

int main(int argc, char* argv[])
{
    boost::thread_group thrds;

    SecurityServer s("sec_server", "7000");

    s.addTopic("topic_1");
    s.addTopic("topic_2");
    s.addTopic("topic_3");

    thrds.create_thread(std::bind(&SecurityServer::serve, &s));

    Publisher p1 = s.addPublisher("publisher_1");
    Publisher p2 = s.addPublisher("publisher_2");
    Subscriber s1 = s.addSubscriber("subscriber_1", "5001");
    Subscriber s2 = s.addSubscriber("subscriber_2", "5002");

    Node n1 = s.addNode("node_1", "6001");
    Node n2 = s.addNode("node_2", "6002");

    thrds.create_thread(std::bind(&Node::serve, &n1));
    thrds.create_thread(std::bind(&Node::serve, &n2));

    p1.addTopic("topic_1", "6001");
    p1.addTopic("topic_3", "6002");
    p2.addTopic("topic_2", "6001");

    n1.addSubscriber("topic_1", "subscriber_1", "5001");
    n2.addSubscriber("topic_3", "subscriber_1", "5001");
    n1.addSubscriber("topic_2", "subscriber_2", "5002");
    n2.addSubscriber("topic_3", "subscriber_2", "5002");

    s1.addTopic("topic_1", "6001");
    s1.addTopic("topic_3", "6002");
    s2.addTopic("topic_2", "6001");
    s2.addTopic("topic_3", "6002");

    thrds.create_thread(std::bind(&Subscriber::serve, &s1));
    thrds.create_thread(std::bind(&Subscriber::serve, &s2));
    thrds.create_thread(std::bind(&Publisher::generateRandom, &p1));
    thrds.create_thread(std::bind(&Publisher::generateRandom, &p2));

    thrds.join_all();

    return 0;
}
