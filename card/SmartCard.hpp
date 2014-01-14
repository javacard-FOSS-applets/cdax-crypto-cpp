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
    public:
        bool selectApplet();
        std::string getError();

        bool transmit(bytestring &updu);

        bool storePrivateKey(CryptoPP::RSA::PrivateKey* privKey);
        bool connect();
        CryptoPP::RSA::PublicKey* initialize(CryptoPP::RSA::PublicKey* secServerPub);

        bool storeKey(bytestring key);

        bool sign(bytestring &msg);
        bool verify(bytestring &msg);

        bool encrypt(bytestring &msg);
        bool decrypt(bytestring &msg);

        bool appendHMAC(bytestring &msg);
        bool verifyHMAC(bytestring &msg);

        bool encryptAES(bytestring &msg);
        bool decryptAES(bytestring &msg);
    };

};
