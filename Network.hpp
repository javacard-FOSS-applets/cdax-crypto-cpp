#pragma once

#include <ctime>
#include <iostream>
#include <string>

#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include "Message.hpp"

namespace cdax {

    class Network
    {
    protected:
        std::string id;
        const std::string ip = "127.0.0.1";
        std::string port = "5000";
        static boost::mutex io_mutex;
        std::string color = GREEN;

        virtual Message handle(Message request);
        Message send(Message request, std::string port);

        void log(std::string text);
        void log(std::string text, Message msg);

    public:
        virtual void serve();
        virtual std::string getPort();

    };

}
