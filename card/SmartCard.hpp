#pragma once

#include <unistd.h>
#include <iostream>
#include <string>
#include <ctime>
#include <sys/time.h>
#include <vector>
#include <numeric>

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
        std::string reader;

        bool debug = false;
        std::vector<double> timer;

        bool selectReader();
        bool waitForCard();
    public:
        void startTimer();
        double getTimerMean();
        double getTimerStdev();

        bool selectApplet();
        std::string getError();

        void setDebug(bool value);

        bool transmit(byte instruction, bytestring &data, byte p1 = 0x00, byte p2 = 0x00);

        bool storeTopicKey(bytestring key, size_t key_index = 0);
        bool storePrivateKey(CryptoPP::RSA::PrivateKey privKey);

        bool handleTopicKeyResponse(bytestring &msg, size_t key_index);

        bool connect();
        void release();

        CryptoPP::RSA::PublicKey initialize(CryptoPP::RSA::PublicKey secServerPub);

        bool sign(bytestring &msg);
        bool verify(bytestring &msg);

        bool encrypt(bytestring &msg);
        bool decrypt(bytestring &msg);

        bool hmac(bytestring &msg, size_t key_index = 0);
        bool hmacVerify(bytestring &msg, size_t key_index = 0);

        bool aesEncrypt(bytestring &msg, size_t key_index = 0);
        bool aesDecrypt(bytestring &msg, size_t key_index = 0);

        bool encode(bytestring &msg, size_t key_index = 0);
        bool decode(bytestring &msg, size_t key_index = 0);
    };

    struct CardException : public std::exception
    {
        std::string s;

        CardException(std::string ss) : s(ss) {}
        ~CardException() throw () {}

        const char* what() const throw()
        {
            return s.c_str();
        }
    };

};
