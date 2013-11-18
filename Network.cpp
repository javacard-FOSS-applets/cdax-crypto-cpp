
#include "Network.hpp"

namespace cdax {

    boost::mutex Network::io_mutex;

    void Network::serve()
    {
        this->log(" listening on port ");
        {
            boost::unique_lock<boost::mutex> scoped_lock(io_mutex);
            std::cout << RED << this->id << " listening on port " << this->port << std::endl;
        }

        boost::asio::io_service io_service;
        boost::asio::ip::tcp::endpoint endpoint(
            boost::asio::ip::address::from_string(this->ip),
            std::atoi(this->port.c_str())
        );
        boost::asio::ip::tcp::acceptor acceptor(io_service, endpoint);

        for (;;)
        {
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

    std::string Network::getPort()
    {
        return this->port;
    }

    Message Network::handle(Message request)
    {
        // function stub, acts as echo server
        return request;
    }

    Message Network::send(Message request, std::string port)
    {
        boost::asio::ip::tcp::iostream stream(ip, port);
        boost::archive::text_oarchive oa(stream);
        oa << request;

        Message response;
        boost::archive::text_iarchive ia(stream);
        ia >> response;

        return response;
    }

    void Network::log(std::string text)
    {
        boost::unique_lock<boost::mutex> scoped_lock(io_mutex);
        std::cout << this->color << this->id << " " << text << std::endl;
    }

    void Network::log(std::string text, Message msg)
    {
        boost::unique_lock<boost::mutex> scoped_lock(io_mutex);
        std::cout << this->color << this->id << " " << text << std::endl << msg;
    }
}
