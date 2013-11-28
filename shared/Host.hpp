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

    /**
     * The host class represents an abract network host
     * It provides methods to listen to network interfaces for incoming
     * TCP connections and to send data over newly created TCP connections.
     * It also includes common utility functions for threads
     * to log data to the screen or to or sleep.
     */
    class Host
    {
    private:
        static boost::mutex io_mutex;

    protected:
        // host identity string
        std::string id;

        // host RSA keypair
        RSAKeyPair key_pair;

        // terminal output color
        std::string color;

        // ip address to listen on
        std::string ip = "127.0.0.1";

        // port number to listen on for TCP connections
        std::string port;

        // security server public key
        CryptoPP::RSA::PublicKey sec_server_key;

        // TCP utility functions
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
