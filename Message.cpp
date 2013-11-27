
#include "Message.hpp"

namespace cdax {

    Message::Message()
    {
        this->timestamp = std::time(0);
    };

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

    void Message::signEncrypt(CryptoPP::SecByteBlock key)
    {
        this->sign(key);
        this->data = this->data + this->signature;
        this->signature.clear();
        this->encrypt(key);
    }

    void Message::verifyDecrypt(CryptoPP::SecByteBlock key)
    {
        this->decrypt(key);
        this->signature = this->data.substr(this->data.size() - 32, 32);
        this->data = this->data.substr(0, this->data.size() - 32);
        this->verify(key);
    }

    void Message::encrypt(CryptoPP::SecByteBlock key)
    {
        generateIV(CryptoPP::AES::BLOCKSIZE);
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encrypt(key, key.size(), this->iv);
        this->data = applyCipher(encrypt);
    }

    void Message::decrypt(CryptoPP::SecByteBlock key)
    {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decrypt(key, key.size(), this->iv);
        this->data = applyCipher(decrypt);
        this->iv.resize(0);
    }

    void Message::sign(CryptoPP::SecByteBlock key)
    {
        this->signature.clear();
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, key.size());
        CryptoPP::StringSink *ss = new CryptoPP::StringSink(this->signature);
        CryptoPP::HashFilter *hf = new CryptoPP::HashFilter(hmac, ss);

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
    }

    void Message::sign(CryptoPP::RSA::PrivateKey key)
    {
        this->signature.clear();
        CryptoPP::AutoSeededRandomPool prng;

        CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(key);
        CryptoPP::StringSink *ss = new CryptoPP::StringSink(this->signature);
        CryptoPP::SignerFilter *sf = new CryptoPP::SignerFilter(prng, signer, ss);

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
        if (msg.iv.size() > 0) {
            out << "message ciper text: " << hex(msg.data) << " iv: " << hex(msg.iv);
        } else {
            out << "message plain text: " << msg.data;
        }

        out << " topic: " << msg.topic << " source: " << msg.id;
        out << " " << std::ctime(&msg.timestamp);

        if (msg.signature.size() > 0) {
            out << "mac/signature: " << hex(msg.signature) << std::endl;
        }

        return out;
    }
}

