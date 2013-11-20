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

    class Host
    {
    protected:
        RSAKeyPair key_pair;
        CryptoPP::RSA::PublicKey sec_server_key;

        std::string id;
        const std::string ip = "127.0.0.1";
        std::string port;
        static boost::mutex io_mutex;
        std::string color;

        virtual Message handle(Message request);
        Message send(Message request, std::string port);

        // utility functions
        void sleep();
        void sleep(int seconds);

        void log(std::string text);
        void log(std::string text, Message msg);

    public:
        virtual void serve();
        virtual std::string getPort();
        virtual std::string getId();

    };

}
