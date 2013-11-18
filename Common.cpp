
#include "Common.hpp"

namespace cdax {

    RSAKeyPair::RSAKeyPair() {};

    RSAKeyPair::RSAKeyPair(CryptoPP::InvertibleRSAFunction params)
    {
         privateKey = CryptoPP::RSA::PrivateKey(params);
         publicKey = CryptoPP::RSA::PublicKey(params);
    }

    CryptoPP::RSA::PrivateKey RSAKeyPair::getPrivate()
    {
        return this->privateKey;
    }

    CryptoPP::RSA::PublicKey RSAKeyPair::getPublic()
    {
        return this->publicKey;
    }

    TopicKeyPair::TopicKeyPair(int enc_len, int auth_len)
    {
        this->encryptionKey = cdax::generateKey(enc_len);
        this->authenticationKey = cdax::generateKey(auth_len);
    }

    TopicKeyPair::TopicKeyPair(std::string source)
    {
        std::stringstream ss(source);
        boost::archive::text_iarchive ia(ss);
        ia >> *this;
    }

    std::string TopicKeyPair::toString()
    {
        std::stringstream ss;
        boost::archive::text_oarchive oa(ss);
        oa << *this;
        return ss.str();
    }

    CryptoPP::SecByteBlock TopicKeyPair::getEncKey()
    {
        return this->encryptionKey;
    }

    CryptoPP::SecByteBlock TopicKeyPair::getAuthKey()
    {
        return this->authenticationKey;
    }

    std::string hex(std::string val)
    {
        std::ostringstream ret;
        ret << '(' << val.length() * 8 << " bit) " << std::hex;
        for (std::string::size_type i = 0; i < val.length(); ++i) {
            ret << std::setfill('0') << std::setw(2) << (int) (val[i] & 0xFF);
        }
        return ret.str();
    }

    std::string hex(CryptoPP::SecByteBlock val)
    {
        std::ostringstream ss;
        ss << '(' << val.size() * 8 << " bit) " << std::hex;
        for(std::size_t i = 0; i < val.size(); ++i) {
            ss << (int) val[i];
        }
        return ss.str();
    }

    std::string hex(CryptoPP::CryptoMaterial *val)
    {
        CryptoPP::ByteQueue bq;
        val->Save(bq);
        CryptoPP::SecByteBlock publicKeyArray((unsigned int)bq.MaxRetrievable());
        bq.Get((byte*)publicKeyArray, publicKeyArray.size());
        return hex(publicKeyArray);
    }

    std::string hex(CryptoPP::RSA::PrivateKey key)
    {
        return hex(&key);
    }

    std::string hex(CryptoPP::RSA::PublicKey key)
    {
        return hex(&key);
    }

    std::string randomString(size_t length)
    {
        auto randchar = []() -> char
        {
            const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const size_t max_index = (sizeof(charset) - 1);
            return charset[rand() % max_index];
        };
        std::string str(length, 0);
        std::generate_n(str.begin(), length, randchar);
        return str;
    }

    CryptoPP::SecByteBlock generateKey(size_t length)
    {
        // Pseudo Random Number Generator
        CryptoPP::AutoSeededRandomPool prng;
        CryptoPP::SecByteBlock key(length);
        prng.GenerateBlock(key, key.size());
        return key;
    }

    RSAKeyPair generateKeyPair(size_t length)
    {
        // Pseudo Random Number Generator
        CryptoPP::AutoSeededRandomPool prng;
        // Generate Parameters
        CryptoPP::InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(prng, length);
        // return keypair
        RSAKeyPair keyPair(params);
        return keyPair;
    }

}
