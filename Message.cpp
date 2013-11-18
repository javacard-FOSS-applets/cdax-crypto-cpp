
#include "Message.hpp"

namespace cdax {

    Message::Message()
    {
        this->timestamp = std::time(0);
    };

    void Message::setCipher(Cipher::CipherType c)
    {
        this->cipher = c;
    }

    Cipher::CipherType Message::getCipher()
    {
        return this->cipher;
    }

    void Message::setData(std::string d)
    {
        this->data = d;
    }

    std::string Message::getData()
    {
        return this->data;
    }

    void Message::setTopic(std::string t)
    {
        this->topic = t;
    }

    std::string Message::getTopic()
    {
        return this->topic;
    }

    void Message::setId(std::string i)
    {
        this->id = i;
    }

    std::string Message::getId()
    {
        return this->id;
    }

    std::string Message::getSignature()
    {
        return this->signature;
    }

    void Message::encrypt(CryptoPP::SecByteBlock key)
    {
        // select algoritm
        switch(this->cipher) {
            case Cipher::Salsa20: {
                generateIV(CryptoPP::Salsa20::IV_LENGTH);
                CryptoPP::Salsa20::Encryption encrypt(key, key.size(), this->iv);
                this->data = applyCipher(encrypt);
                break;
            }
            case Cipher::AES_CBC: {
                generateIV(CryptoPP::AES::BLOCKSIZE);
                CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encrypt(key, key.size(), this->iv);
                this->data = applyCipher(encrypt);
                break;
            }
            case Cipher::AES_GCM: {
                std::string cipertext;
                const int TAG_SIZE = 12;
                generateIV(CryptoPP::AES::BLOCKSIZE * 16);
                CryptoPP::GCM<CryptoPP::AES>::Encryption encrypt;
                encrypt.SetKeyWithIV(key, key.size(), this->iv, this->iv.size());
                CryptoPP::StringSink* sink = new CryptoPP::StringSink(cipertext);
                CryptoPP::StreamTransformationFilter* enc = new CryptoPP::AuthenticatedEncryptionFilter(encrypt, sink, false, TAG_SIZE);
                CryptoPP::StringSource(this->data, true, enc);
                this->data = cipertext;
                break;
            }
            case Cipher::RSA: {
                std::cerr << "Wrong key type for RSA decryption." << std::endl;
                break;
            }
        }
        this->encrypted = true;
    }

    void Message::decrypt(CryptoPP::SecByteBlock key)
    {
        // select algoritm
        switch(this->cipher) {
            case Cipher::Salsa20: {
                CryptoPP::Salsa20::Decryption decrypt(key, key.size(), this->iv);
                this->data = applyCipher(decrypt);
                break;
            }
            case Cipher::AES_CBC: {
                CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decrypt(key, key.size(), this->iv);
                this->data = applyCipher(decrypt);
                break;
            }
            case Cipher::AES_GCM: {
                std::string plaintext;
                const int TAG_SIZE = 12;
                CryptoPP::GCM<CryptoPP::AES>::Decryption decrypt;
                decrypt.SetKeyWithIV(key, key.size(), this->iv, this->iv.size());
                CryptoPP::StringSink* sink = new CryptoPP::StringSink(plaintext);
                const int flags = CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS;
                CryptoPP::AuthenticatedDecryptionFilter df(decrypt, sink, flags, TAG_SIZE);
                CryptoPP::StringSource(this->data, true, new CryptoPP::Redirector(df));
                this->data = plaintext;
                break;
            }
            case Cipher::RSA: {
                std::cerr << "Wrong key type for RSA encryption." << std::endl;
                break;
            }
        }
        this->encrypted = false;
    }

    void Message::sign(CryptoPP::SecByteBlock key)
    {
        this->signature.clear();
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, key.size());
        CryptoPP::StringSink *ss = new CryptoPP::StringSink(this->signature);
        CryptoPP::HashFilter *hf = new CryptoPP::HashFilter(hmac, ss);

        this->authenticated = true;
        CryptoPP::StringSource(this->getPayloadData(), true, hf);
    }

    void Message::verify(CryptoPP::SecByteBlock key)
    {
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, key.size());
        const int flags = CryptoPP::HashVerificationFilter::THROW_EXCEPTION;
        CryptoPP::HashVerificationFilter *hvf = new CryptoPP::HashVerificationFilter(hmac, NULL, flags);
        CryptoPP::StringSource(this->getPayloadData() + this->signature, true, hvf);
    }

    void Message::encrypt(CryptoPP::RSA::PublicKey key)
    {
        std::string ciphertext;
        CryptoPP::AutoSeededRandomPool prng;

        CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(key);
        CryptoPP::StringSink *ss = new CryptoPP::StringSink(ciphertext);
        CryptoPP::PK_EncryptorFilter *ef = new CryptoPP::PK_EncryptorFilter(prng, encryptor, ss);
        CryptoPP::StringSource(this->data, true, ef);

        this->data = ciphertext;
        this->encrypted = true;
        this->cipher = Cipher::RSA;
    }

    void Message::decrypt(CryptoPP::RSA::PrivateKey key)
    {
        std::string plaintext;
        CryptoPP::AutoSeededRandomPool prng;

        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(key);
        CryptoPP::StringSink *ss = new CryptoPP::StringSink(plaintext);
        CryptoPP::PK_DecryptorFilter *df = new CryptoPP::PK_DecryptorFilter(prng, decryptor, ss);
        CryptoPP::StringSource(this->data, true, df);

        this->data = plaintext;
        this->encrypted = false;
    }

    void Message::sign(CryptoPP::RSA::PrivateKey key)
    {
        this->signature.clear();
        CryptoPP::AutoSeededRandomPool prng;

        CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(key);
        CryptoPP::StringSink *ss = new CryptoPP::StringSink(this->signature);
        CryptoPP::SignerFilter *sf = new CryptoPP::SignerFilter(prng, signer, ss);

        this->authenticated = true;
        CryptoPP::StringSource(this->getPayloadData(), true, sf);
    }

    void Message::verify(CryptoPP::RSA::PublicKey key)
    {
        CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(key);
        const int flags = CryptoPP::SignatureVerificationFilter::THROW_EXCEPTION;
        CryptoPP::SignatureVerificationFilter *svf = new CryptoPP::SignatureVerificationFilter(verifier, NULL, flags);
        CryptoPP::StringSource(this->getPayloadData() + this->signature, true, svf);
    }

    void Message::generateIV(int length)
    {
        CryptoPP::AutoSeededRandomPool prng;
        this->iv = CryptoPP::SecByteBlock(length);
        prng.GenerateBlock(this->iv, length);
    }

    std::string Message::getPayloadData()
    {
        std::stringstream ss;

        ss << this->id;
        ss << this->topic;
        ss << this->data;

        std::string tmp_timestamp = boost::lexical_cast<std::string>(this->timestamp);
        ss << tmp_timestamp;

        std::string tmp_iv = std::string(this->iv.begin(), this->iv.end());
        ss << tmp_iv;

        std::string tmp_cipher = boost::lexical_cast<std::string>(this->cipher);
        ss << tmp_cipher;

        return ss.str();
    }

    std::string Message::applyCipher(CryptoPP::StreamTransformation &t)
    {
        std::string result;
        CryptoPP::StringSink* sink = new CryptoPP::StringSink(result);
        CryptoPP::StreamTransformationFilter* enc = new CryptoPP::StreamTransformationFilter(t, sink);
        CryptoPP::StringSource(this->data, true, enc);
        return result;
    }

    std::ostream &operator<< (std::ostream &out, const Message &msg)
    {
        if (!msg.encrypted) {
            out << "message: " << msg.data << std::endl << "topic: " << msg.topic;
            out << " sender: " << msg.id << " date: " << std::ctime(&msg.timestamp);
        } else {
            out << "message: " << hex(msg.data) << std::endl << "topic: " << msg.topic;
            out << " sender: " << msg.id << " date: " << std::ctime(&msg.timestamp);
            out << "encryption: " << Cipher::CipherString[msg.cipher];
            out << " iv: " << hex(msg.iv) << std::endl;
        }

        if (msg.authenticated) {
            out << "mac/signature: " << hex(msg.signature) << std::endl;
        }

        return out;
    }
}

