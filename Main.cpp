
#include <boost/lexical_cast.hpp>

#include "servers/SecurityServer.hpp"
#include "servers/Node.hpp"
#include "clients/Publisher.hpp"
#include "clients/Subscriber.hpp"

using namespace cdax;

void advanced()
{
    // new thread pool
    boost::thread_group thrds;

    SecurityServer *s = new SecurityServer("sec_server", "7000");

    s->addTopic("topic_1");
    s->addTopic("topic_2");
    s->addTopic("topic_3");

    // create treads security server main loop
    // this is needed to handle topic key request
    // when adding new topics to nodes
    thrds.create_thread(std::bind(&SecurityServer::serve, s));

    SmartCard *card = new SmartCard();

    Publisher *p1 = s->addPublisher("publisher_1");
    Publisher *p2 = s->addPublisher("publisher_2");
    Subscriber *s1 = s->addSubscriber("subscriber_1", "5001");
    Subscriber *s2 = s->addSubscriber("subscriber_2", "5002");

    Node *n1 = s->addNode("node_1", "6001");
    Node *n2 = s->addNode("node_2", "6002");

    // create treads from each host main loop
    // this is needed to handle topic join requests from the clients
    thrds.create_thread(std::bind(&Node::serve, n1));
    thrds.create_thread(std::bind(&Node::serve, n2));

    p1->addTopic("topic_1", "6001");
    p1->addTopic("topic_3", "6002");
    p2->addTopic("topic_2", "6001");

    n1->addSubscriber("topic_1", "subscriber_1", "5001");
    n2->addSubscriber("topic_3", "subscriber_1", "5001");
    n1->addSubscriber("topic_2", "subscriber_2", "5002");
    n2->addSubscriber("topic_3", "subscriber_2", "5002");

    s1->addTopic("topic_1", "6001");
    s1->addTopic("topic_3", "6002");
    s2->addTopic("topic_2", "6001");
    s2->addTopic("topic_3", "6002");

    // create treads from each host main loop
    thrds.create_thread(std::bind(&Subscriber::serve, s1));
    thrds.create_thread(std::bind(&Subscriber::serve, s2));
    thrds.create_thread(std::bind(&Publisher::generateRandom, p1));
    thrds.create_thread(std::bind(&Publisher::generateRandom, p2));

    // wait for all threads to terminate
    thrds.join_all();
}

void simple()
{
    // new thread pool
    boost::thread_group thrds;

    SecurityServer *s = new SecurityServer("sec_server", "7000");
    s->addTopic("test_topic");

    // create treads security server main loop
    // this is needed to handle topic key request
    // when adding new topics to nodes
    thrds.create_thread(std::bind(&SecurityServer::serve, s));

    Publisher *p1 = s->addPublisher("publisher");
    Subscriber *s1 = s->addSubscriber("subscriber", "5001");
    Node *n1 = s->addNode("node", "6001");

    // create treads from each host main loop
    // this is needed to handle topic join requests from the clients
    thrds.create_thread(std::bind(&Node::serve, n1));

    p1->addTopic("test_topic", "6001");
    n1->addSubscriber("test_topic", "subscriber", "5001");
    s1->addTopic("test_topic", "6001");

    // create treads from each host main loop
    thrds.create_thread(std::bind(&Subscriber::serve, s1));

    // publish test message
    p1->publishMessage("test_topic", "hello world");

    // wait for all threads to terminate
    thrds.join_all();
}

/**
 * Setup a simulated CDAX system, in which hosts like clients or nodes
 * are modelled by threads, each having a unique port number, to setup TCP connections
 * @param  argc ignored
 * @param  argv ignored
 * @return int response code
 */
int main(int argc, char* argv[])
{
    // advanced();
    simple();

    return 0;
}
