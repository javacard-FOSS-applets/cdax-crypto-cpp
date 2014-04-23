
#include "RSAKeyPair.hpp"

CryptoPP::AutoSeededRandomPool prng;

namespace cdax {

    RSAKeyPair::RSAKeyPair()
    {

    }

    /**
     * Construct a new RSA keypair using the RSa params
     *
     * @param params CryptoPP::InvertibleRSAFunction params
     */
    RSAKeyPair::RSAKeyPair(int length)
    {
        this->privateKey.GenerateRandomWithKeySize(prng, length);
        this->publicKey = CryptoPP::RSA::PublicKey(this->privateKey);
    }

    RSAKeyPair::RSAKeyPair(CryptoPP::RSA::PublicKey pub, CryptoPP::RSA::PrivateKey priv)
    {
        this->publicKey = pub;
        this->privateKey = priv;
    }

    RSAKeyPair::~RSAKeyPair()
    {

    }

    void RSAKeyPair::setPublic(CryptoPP::RSA::PublicKey pub)
    {
        this->publicKey = pub;
    }

    void RSAKeyPair::setPrivate(CryptoPP::RSA::PrivateKey priv)
    {
        this->privateKey = priv;
    }

    /**
     * Retrieve the private key part
     * @return CryptoPP::RSA::PrivateKey private key
     */
    CryptoPP::RSA::PrivateKey RSAKeyPair::getPrivate()
    {
        return this->privateKey;
    }

    /**
     * Retrieve the public key part
     * @return CryptoPP::RSA::PublicKey public key
     */
    CryptoPP::RSA::PublicKey RSAKeyPair::getPublic()
    {
        return this->publicKey;
    }

    void RSAKeyPair::saveKey(std::string filename, CryptoPP::RSA::PrivateKey key)
    {
        CryptoPP::ByteQueue queue;
        key.Save(queue);
        CryptoPP::FileSink file(filename.c_str());
        queue.CopyTo(file);
        file.MessageEnd();
    }

    void RSAKeyPair::saveKey(std::string filename, CryptoPP::RSA::PublicKey key)
    {
        CryptoPP::ByteQueue queue;
        key.Save(queue);
        CryptoPP::FileSink file(filename.c_str());
        queue.CopyTo(file);
        file.MessageEnd();
    }

    CryptoPP::RSA::PublicKey RSAKeyPair::loadPubKey(std::string filename)
    {
        CryptoPP::RSA::PublicKey key;
        CryptoPP::ByteQueue queue;
        CryptoPP::FileSource file(filename.c_str(), true);

        file.TransferTo(queue);
        queue.MessageEnd();

        key.Load(queue);
        return key;
    }

    CryptoPP::RSA::PrivateKey RSAKeyPair::loadPrivKey(std::string filename)
    {
        CryptoPP::RSA::PrivateKey key;
        CryptoPP::ByteQueue queue;
        CryptoPP::FileSource file(filename.c_str(), true);

        file.TransferTo(queue);
        queue.MessageEnd();

        key.Load(queue);
        return key;
    }

}
