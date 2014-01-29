
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
    RSAKeyPair::RSAKeyPair(CryptoPP::InvertibleRSAFunction &params)
    {
         privateKey = new CryptoPP::RSA::PrivateKey(params);
         publicKey = new CryptoPP::RSA::PublicKey(params);
    }

    RSAKeyPair::RSAKeyPair(CryptoPP::RSA::PublicKey* pub, CryptoPP::RSA::PrivateKey* priv)
    {
        publicKey = pub;
        privateKey = priv;
    }

    /**
     * Retrieve the private key part
     * @return CryptoPP::RSA::PrivateKey private key
     */
    CryptoPP::RSA::PrivateKey* RSAKeyPair::getPrivate()
    {
        return this->privateKey;
    }

    /**
     * Retrieve the public key part
     * @return CryptoPP::RSA::PublicKey public key
     */
    CryptoPP::RSA::PublicKey* RSAKeyPair::getPublic()
    {
        return this->publicKey;
    }

    void RSAKeyPair::saveKey(std::string filename, CryptoPP::CryptoMaterial* key)
    {
        CryptoPP::ByteQueue queue;
        key->Save(queue);

        CryptoPP::FileSink file(filename.c_str());

        queue.CopyTo(file);
        file.MessageEnd();
    }

    void RSAKeyPair::savePrivKey(std::string filename, CryptoPP::RSA::PrivateKey* key)
    {
        saveKey(filename, (CryptoPP::CryptoMaterial*) key);
    }

    void RSAKeyPair::savePubKey(std::string filename, CryptoPP::RSA::PublicKey* key)
    {
        saveKey(filename, (CryptoPP::CryptoMaterial*) key);
    }

    void RSAKeyPair::loadKey(std::string filename, CryptoPP::CryptoMaterial* key)
    {
        CryptoPP::ByteQueue queue;
        CryptoPP::FileSource file(filename.c_str(), true);

        file.TransferTo(queue);
        queue.MessageEnd();

        key->Load(queue);
    }

    CryptoPP::RSA::PublicKey* RSAKeyPair::loadPubKey(std::string filename)
    {
        CryptoPP::RSA::PublicKey* key = new CryptoPP::RSA::PublicKey();
        loadKey(filename, (CryptoPP::CryptoMaterial*) key);
        return key;
    }

    CryptoPP::RSA::PrivateKey* RSAKeyPair::loadPrivKey(std::string filename)
    {
        CryptoPP::RSA::PrivateKey* key = new CryptoPP::RSA::PrivateKey();
        loadKey(filename, (CryptoPP::CryptoMaterial*) key);
        return key;
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
        this->encryptionKey = source.substr(0, len);
        // last TopicKeyPair::KeyLength bytes are the authentication key
        this->authenticationKey = source.substr(len, len);
    }

    /**
     * Construct a topic key pair from a string, the first
     * TopicKeyPair::KeyLength bytes in the string are the
     * encryption key the last TopicKeyPair::KeyLength bytes
     * are used as the the authentication key.
     * @param string key source
     */
    TopicKeyPair::TopicKeyPair(bytestring source)
    {
        int len = TopicKeyPair::KeyLength;
        // first TopicKeyPair::KeyLength bytes are the encyption key
        this->encryptionKey = source.str().substr(0, len);
        // last TopicKeyPair::KeyLength bytes are the authentication key
        this->authenticationKey = source.str().substr(len, len);
    }

    /**
     * Create a topic key pair from two bytestring values
     * @param bytestring enc_key encryption key
     * @param bytestring auth_key authentication key
     */
    TopicKeyPair::TopicKeyPair(bytestring enc_key, bytestring auth_key)
    {
        this->encryptionKey = enc_key;
        this->authenticationKey = auth_key;
    }

    bytestring TopicKeyPair::getValue()
    {
        bytestring buffer;
        buffer.Assign(this->encryptionKey + this->authenticationKey);
        return buffer;
    }

    /**
     * Encode the topic keys as a string
     * @return string topic keys
     */
    std::string TopicKeyPair::toString()
    {
        return this->encryptionKey.str() + this->authenticationKey.str();
    }

    /**
     * Get encryption key
     * @return bytestring encryption key
     */
    bytestring TopicKeyPair::getEncKey() const
    {
        return this->encryptionKey;
    }

    /**
     * Get the authentication key
     * @return bytestring authentication key
     */
    bytestring TopicKeyPair::getAuthKey() const
    {
        return this->authenticationKey;
    }

    bytestring::bytestring(std::string source)
    {
        this->Assign((const unsigned char*) source.c_str(), source.size());
    }

    bytestring::bytestring(const char* source)
    {
        this->Assign((const unsigned char*) source, strlen(source) + 1);
    }

    void bytestring::clear()
    {
        this->resize(0);
    }

    const std::string bytestring::hex() const
    {
        std::ostringstream ss;
        ss << '(' << this->size() << " byte) " << std::hex;
        for(std::size_t i = 0; i < this->size(); ++i) {
            if (i != 0) {
                ss << ':';
            }
            ss << (int) (*this)[i];
        }
        return ss.str();
    }

    const std::string bytestring::str() const
    {
        return std::string(this->begin(), this->end());
    }

    bytestring bytestring::substr(size_t offset, size_t size)
    {
        bytestring result(size);
        result.Assign(this->BytePtr() + offset, size);
        return result;
    }

    /**
     * Overload << operator, to format the content of a message
     * in an output stream. Shows the message data, sender id,
     * topic name and message timestamp
     */
    std::ostream &operator<< (std::ostream &out, const bytestring &data)
    {
        out << std::string(data.m_ptr, data.m_ptr + data.m_size);
        return out;
    }

    std::size_t hash_value(bytestring const& b)
    {
        boost::hash<std::string> hasher;
        return hasher(b.str());
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
     * Format bytestring as HEX string
     * @param  bytestring val input value
     * @return string the HEX formatted string
     */
    std::string hex(bytestring val)
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
        bytestring publicKeyArray((unsigned int)bq.MaxRetrievable());
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


    bool file_exists(const std::string& fileName)
    {
        std::ifstream infile(fileName);
        return infile.good();
    }

}
