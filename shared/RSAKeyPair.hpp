#pragma once

#include <cstdlib>
#include <string>

#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

namespace cdax {

    /**
     * Container class of a RSA keypair, holds the default keylength
     */
    class RSAKeyPair
    {
    private:
        CryptoPP::RSA::PublicKey publicKey;
        CryptoPP::RSA::PrivateKey privateKey;

    public:
        static const int KeyLength = 2048;

        RSAKeyPair();
        RSAKeyPair(CryptoPP::RSA::PublicKey pub, CryptoPP::RSA::PrivateKey priv);
        RSAKeyPair(CryptoPP::InvertibleRSAFunction &params);

        void setPublic(CryptoPP::RSA::PublicKey pub);
        void setPrivate(CryptoPP::RSA::PrivateKey priv);

        CryptoPP::RSA::PublicKey getPublic();
        CryptoPP::RSA::PrivateKey getPrivate();

        // template <class T>
        // static void saveKey(std::string filename, T key);

        // template <class T>
        // static T loadKey(std::string filename);

        static void saveKey(std::string filename, CryptoPP::RSA::PublicKey key);
        static void saveKey(std::string filename, CryptoPP::RSA::PrivateKey key);

        static CryptoPP::RSA::PublicKey loadPubKey(std::string filename);
        static CryptoPP::RSA::PrivateKey loadPrivKey(std::string filename);
    };

}
