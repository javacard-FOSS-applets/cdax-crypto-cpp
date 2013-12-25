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

        bool selectReader();
        bool waitForCard();
        bool selectApplet();

        bool transmit(bytestring &updu);
    public:
        std::string getError();

        bool storePrivateKey(CryptoPP::RSA::PrivateKey* privKey);
        bool connect();
        CryptoPP::RSA::PublicKey* initialize(CryptoPP::RSA::PublicKey* secServerPub);

        bool signMessage(bytestring &msg);
    };

};
