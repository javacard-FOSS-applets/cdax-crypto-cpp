
#include "Host.hpp"

namespace cdax {

    // stdout mutex, to prevent log messages from overlapping
    boost::mutex Host::io_mutex;

    /**
     * Get the host identity as string
     * @return string identity
     */
    bytestring Host::getId()
    {
        return this->id;
    }

    /**
     * Get the host network port
     * @return string the port number as string
     */
    std::string Host::getPort()
    {
        return this->port;
    }

    /**
     * Main loop that listens for incoming TCP connections
     * All TCP messages are passed to the Host::handle function
     */
    void Host::serve()
    {
        this->log("listening on port " + this->port);

        // listen for tcp connections
        boost::asio::io_service io_service;
        boost::asio::ip::tcp::endpoint endpoint(
            boost::asio::ip::address::from_string(this->ip),
            std::atoi(this->port.c_str())
        );
        boost::asio::ip::tcp::acceptor acceptor(io_service, endpoint);

        for (;;)
        {
            // receive and reply with Message instances
            boost::asio::ip::tcp::iostream stream;
            acceptor.accept(*stream.rdbuf());

            Message request;
            boost::archive::text_iarchive ia(stream);
            ia >> request;

            Message response = this->handle(request);
            boost::archive::text_oarchive oa(stream);

            oa << response;
        }
    }

    /**
     * Handle a message and return a message response
     * @param  Message request the request message
     * @return Message the response message
     */
    Message Host::handle(Message request)
    {
        // function stub, acts as echo server
        return request;
    }

    /**
     * Create a new TCP connection, send and subsequently receive a message
     * @param  Message request the request message
     * @param  string port the port number to send te message to
     * @return Message the response message
     */
    Message Host::send(Message request, std::string port)
    {
        // open new tcp connection
        boost::asio::ip::tcp::iostream stream(this->ip, port);
        boost::archive::text_oarchive oa(stream);

        // send Message
        oa << request;

        // receive Message response
        Message response;
        boost::archive::text_iarchive ia(stream);
        ia >> response;

        return response;
    }

    /**
     * Sleep a random amount of time
     */
    void Host::sleep()
    {
        // random value between 2 and 4 seconds
        int random = 2000 + std::rand() % 2000;
        boost::this_thread::sleep(boost::posix_time::milliseconds(random));
    }

    /**
     * Sleep for `seconds` seconds
     * @param int seconds
     */
    void Host::sleep(int seconds)
    {
        boost::this_thread::sleep(boost::posix_time::seconds(seconds));
    }

    /**
     * Log text to the console
     * The defined host color is used
     * @param string text
     */
    void Host::log(const std::string text)
    {
        boost::unique_lock<boost::mutex> scoped_lock(io_mutex);
        std::cout << this->color << this->id.str() << " " << text << std::endl;
    }

    /**
     * Log text and a message to the console
     * The defined host color is used
     * @param string text
     * @param Message message
     */
    void Host::log(const std::string text, Message msg)
    {
        boost::unique_lock<boost::mutex> scoped_lock(io_mutex);
        std::cout << this->color << this->id.str() << " " << text << std::endl << msg;
    }
}
