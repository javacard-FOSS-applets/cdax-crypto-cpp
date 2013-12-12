
#include "Common.hpp"

namespace cdax {

    /**
     * Empty contructor
     */
    RSAKeyPair::RSAKeyPair()
    {
        // pass
    }

    /**
     * Construct a new RSA keypair using the RSa params
     *
     * @param params CryptoPP::InvertibleRSAFunction params
     */
    RSAKeyPair::RSAKeyPair(CryptoPP::InvertibleRSAFunction params)
    {
         privateKey = CryptoPP::RSA::PrivateKey(params);
         publicKey = CryptoPP::RSA::PublicKey(params);
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

    /**
     * Empty contructor
     */
    TopicKeyPair::TopicKeyPair()
    {
        // pass
    }

    /**
     * Construct a topic key pair from a string, the first
     * TopicKeyPair::KeyLength bytes in the string are the
     * encryption key the last TopicKeyPair::KeyLength bytes
     * are used as the the authentication key.
     * @param string key source
     */
    TopicKeyPair::TopicKeyPair(std::string source)
    {
        int len = TopicKeyPair::KeyLength;
        // first TopicKeyPair::KeyLength bytes are the encyption key
        this->encryptionKey = stringToSec(source.substr(0, len));
        // last TopicKeyPair::KeyLength bytes are the authentication key
        this->authenticationKey = stringToSec(source.substr(len, len));
    }

    /**
     * Create a topic key pair from two CryptoPP::SecByteBlock values
     * @param CryptoPP::SecByteBlock enc_key encryption key
     * @param CryptoPP::SecByteBlock auth_key authentication key
     */
    TopicKeyPair::TopicKeyPair(CryptoPP::SecByteBlock enc_key, CryptoPP::SecByteBlock auth_key)
    {
        this->encryptionKey = enc_key;
        this->authenticationKey = auth_key;
    }

    /**
     * Encode the topic keys as a string
     * @return string topic keys
     */
    std::string TopicKeyPair::toString()
    {
        return secToString(this->encryptionKey) + secToString(this->authenticationKey);
    }

    /**
     * Get encryption key
     * @return CryptoPP::SecByteBlock encryption key
     */
    CryptoPP::SecByteBlock TopicKeyPair::getEncKey()
    {
        return this->encryptionKey;
    }

    /**
     * Get the authentication key
     * @return CryptoPP::SecByteBlock authentication key
     */
    CryptoPP::SecByteBlock TopicKeyPair::getAuthKey()
    {
        return this->authenticationKey;
    }

    /**
     * convert string to CryptoPP::SecByteBlock
     * @param  str string source
     * @return CryptoPP::SecByteBlock
     */
    CryptoPP::SecByteBlock stringToSec(std::string str)
    {
        CryptoPP::SecByteBlock block(str.size());
        block.Assign((const unsigned char*) str.c_str(), str.size());
        return block;
    }

    /**
     * Convert CryptoPP::SecByteBlock to string
     * @param  CryptoPP::SecByteBlock block source
     * @return string
     */
    std::string secToString(CryptoPP::SecByteBlock block)
    {
        return std::string(block.begin(), block.end());
    }

    /**
     * Format byte array as HEX string
     * @param byte[]] val input value
     * @param size_t val input value
     * @return string HEX formatted string
     */
     std::string hex(byte val[], size_t len)
     {
         std::ostringstream ss;
         ss << '(' << len  << " byte) " << std::hex;
         for (std::size_t i = 0; i < len; ++i) {
             if (i != 0) {
                 ss << ':';
             }
             ss << std::setfill('0') << std::setw(2) << (int) (val[i] & 0xFF);
         }
         return ss.str();
     }

    /**
     * Format string as HEX string
     * @param  string val input value
     * @return string the HEX formatted string
     */
    std::string hex(std::string val)
    {
        std::ostringstream ss;
        ss << '(' << val.length() << " byte) " << std::hex;
        for (std::string::size_type i = 0; i < val.length(); ++i) {
            if (i != 0) {
                ss << ':';
            }
            ss << std::setfill('0') << std::setw(2) << (int) (val[i] & 0xFF);
        }
        return ss.str();
    }

    /**
     * Format CryptoPP::SecByteBlock as HEX string
     * @param  CryptoPP::SecByteBlock val input value
     * @return string the HEX formatted string
     */
    std::string hex(CryptoPP::SecByteBlock val)
    {
        std::ostringstream ss;
        ss << '(' << val.size() << " byte) " << std::hex;
        for(std::size_t i = 0; i < val.size(); ++i) {
            if (i != 0) {
                ss << ':';
            }
            ss << (int) val[i];
        }
        return ss.str();
    }

    /**
     * Format CryptoPP::CryptoMaterial as HEX string
     * @param  CryptoPP::CryptoMaterial val input value
     * @return string the HEX formatted string
     */
    std::string hex(CryptoPP::CryptoMaterial *val)
    {
        CryptoPP::ByteQueue bq;
        val->Save(bq);
        CryptoPP::SecByteBlock publicKeyArray((unsigned int)bq.MaxRetrievable());
        bq.Get((byte*)publicKeyArray, publicKeyArray.size());
        return hex(publicKeyArray);
    }

    /**
     * Format CryptoPP::RSA::PrivateKey as HEX string
     * @param  CryptoPP::RSA::PrivateKey val input value
     * @return string the HEX formatted string
     */
    std::string hex(CryptoPP::RSA::PrivateKey key)
    {
        return hex(&key);
    }

    /**
     * Format CryptoPP::RSA::PublicKey as HEX string
     * @param  CryptoPP::RSA::PublicKey val input value
     * @return string the HEX formatted string
     */
    std::string hex(CryptoPP::RSA::PublicKey key)
    {
        return hex(&key);
    }

    /**
     * Generate a random string of `length` characters/bytes
     * @param  int length the string length
     * @return string the resulting random string
     */
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

}
