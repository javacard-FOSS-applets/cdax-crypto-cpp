#pragma once

#include <unistd.h>
#include <iostream>
#include <string>

#include <cryptopp/rsa.h>

#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>

#include "../shared/Common.hpp"

namespace cdax {

    class SmartCard
    {

    private:
        PCSC_API::SCARDCONTEXT context;
        PCSC_API::SCARDHANDLE card;
        PCSC_API::DWORD active_protocol;

        std::string last_error;
        char* reader;

    public:
        std::string getError();
        bool selectReader();
        bool waitForCard();
        bool selectApplet();
        bool transmit(byte* apdu, size_t &apdu_len);
        bool signMessage(byte* msg, size_t &msg_len);
        bool storePrivateKey(CryptoPP::InvertibleRSAFunction params);

    };

};
