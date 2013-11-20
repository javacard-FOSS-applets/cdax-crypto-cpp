
#include "Host.hpp"

namespace cdax {

    boost::mutex Host::io_mutex;

    void Host::serve()
    {
        this->log("listening on port " + this->port);

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

    std::string Host::getId()
    {
        return this->id;
    }

    std::string Host::getPort()
    {
        return this->port;
    }

    Message Host::handle(Message request)
    {
        // function stub, acts as echo server
        return request;
    }

    Message Host::send(Message request, std::string port)
    {
        boost::asio::ip::tcp::iostream stream(this->ip, port);
        boost::archive::text_oarchive oa(stream);

        oa << request;

        Message response;
        boost::archive::text_iarchive ia(stream);
        ia >> response;

        return response;
    }

    void Host::sleep()
    {
        int random = 2000 + std::rand() % 2000;
        boost::this_thread::sleep(boost::posix_time::milliseconds(random));
    }

    void Host::sleep(int seconds)
    {
        boost::this_thread::sleep(boost::posix_time::seconds(seconds));
    }

    void Host::log(std::string text)
    {
        boost::unique_lock<boost::mutex> scoped_lock(io_mutex);
        std::cout << this->color << this->id << " " << text << std::endl;
    }

    void Host::log(std::string text, Message msg)
    {
        boost::unique_lock<boost::mutex> scoped_lock(io_mutex);
        std::cout << this->color << this->id << " " << text << std::endl << msg;
    }
}
