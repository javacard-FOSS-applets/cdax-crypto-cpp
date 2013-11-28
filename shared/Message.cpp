
#include "Message.hpp"

namespace cdax {

    /**
     * Message constructor, set current time in timestamp
     */
    Message::Message()
    {
        this->timestamp = std::time(0);
    }

    /**
     * Message constructor
     * @param string identity    name of the sender
     * @param string topic_name  name of the topic
     * @param string topic_data  message payload/topic data
     */
    Message::Message(std::string identity, std::string topic_name, std::string topic_data)
    {
        this->timestamp = std::time(0);

        this->id = identity;
        this->topic = topic_name;
        this->data = topic_data;
    }

    /**
     * Set the name of the sender
     * @param string identity
     */
    void Message::setId(std::string identity)
    {
        this->id = identity;
    }

    /**
     * Get the name of the sender
     * @param string topic_name
     */
    void Message::setTopic(std::string topic_name)
    {
        this->topic = topic_name;
    }

    /**
     * Get the topic name
     * @return string topic name
     */
    std::string Message::getTopic()
    {
        return this->topic;
    }

    /**
     * Get the sender identity
     * @return string identity
     */
    std::string Message::getId()
    {
        return this->id;
    }

    /**
     * Set the message topic data/payload
     * @param string topic_data
     */
    void Message::setData(std::string topic_data)
    {
        this->data = topic_data;
    }

    /**
     * Get the message topic data/payload
     * @return string topic data
     */
    std::string Message::getData()
    {
        return this->data;
    }

    /**
     * Get the message signature or HMAC code as a string
     * @return string HMAC or RSA signature
     */
    std::string Message::getSignature()
    {
        return this->signature;
    }

    /**
     * HMAC and AES encrypt the message using the same key.
     * The HMAC is appended to the message topic data before encrypting
     * @param CryptoPP::SecByteBlock key
     */
    void Message::hmacAndEncrypt(CryptoPP::SecByteBlock key)
    {
        this->hmac(key);
        this->data = this->data + this->signature;
        this->signature.clear();
        this->encrypt(key);
    }

    /**
     * AES decrypt the message and verify the HMAC
     * @param  CryptoPP::SecByteBlock key AES and HMAC key
     * @return bool true if decryption and verification are successful
     */
    bool Message::decryptAndVerify(CryptoPP::SecByteBlock key)
    {
        bool result = this->decrypt(key);

        if (!result) {
            return false;
        }

        this->signature = this->data.substr(this->data.size() - 32, 32);
        this->data = this->data.substr(0, this->data.size() - 32);

        return this->verify(key);
    }

    /**
     * Encrypt the message topic data using AES CBC and a fresh random IV
     * @param CryptoPP::SecByteBlock key encryption key
     */
    void Message::encrypt(CryptoPP::SecByteBlock key)
    {
        generateIV(CryptoPP::AES::BLOCKSIZE);
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encrypt(key, key.size(), this->iv);
        this->data = applyCipher(encrypt);
    }

    /**
     * Decrypt the AES CBC encrypted message payload
     * This requires the correct IV attribute to be set.
     * @param  CryptoPP::SecByteBlock key AES key
     * @return bool true if decryption was successful
     */
    bool Message::decrypt(CryptoPP::SecByteBlock key)
    {
        try {
            CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decrypt(key, key.size(), this->iv);
            this->data = applyCipher(decrypt);
            this->iv.resize(0);

            return true;
        } catch(const CryptoPP::Exception& e) {

            return false;
        }
    }

    /**
     * Add HMAC to the message, using the sender id, message timestamp,
     * topic name, topic data and possibly the encryption IV as payload data
     * @param CryptoPP::SecByteBlock key HMAC key
     */
    void Message::hmac(CryptoPP::SecByteBlock key)
    {
        this->signature.clear();
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, key.size());
        CryptoPP::StringSink *ss = new CryptoPP::StringSink(this->signature);
        CryptoPP::HashFilter *hf = new CryptoPP::HashFilter(hmac, ss);

        CryptoPP::StringSource(this->getPayloadData(), true, hf);
    }

    /**
     * Verify the message HMAC
     * @param  CryptoPP::SecByteBlock key HMAC key
     * @return bool true if the verification was successful
     */
    bool Message::verify(CryptoPP::SecByteBlock key)
    {
        try {
            CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, key.size());
            const int flags = CryptoPP::HashVerificationFilter::THROW_EXCEPTION | CryptoPP::HashVerificationFilter::HASH_AT_END;
            CryptoPP::HashVerificationFilter *hvf = new CryptoPP::HashVerificationFilter(hmac, NULL, flags);
            CryptoPP::StringSource(this->getPayloadData() + this->signature, true, hvf);

            return true;
        } catch(const CryptoPP::Exception& e) {

            return false;
        }
    }

    /**
     * Encrypt the message payload data with RSA RSAES OAEP SHA
     * @param CryptoPP::RSA::PublicKey key the RSA public key to use
     */
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

    /**
     * Decrypt the message payload data with RSA RSAES OAEP SHA
     * @param  CryptoPP::RSA::PrivateKey key the private key
     * @return bool true if decryption was successful
     */
    bool Message::decrypt(CryptoPP::RSA::PrivateKey key)
    {
        std::string plaintext;
        CryptoPP::AutoSeededRandomPool prng;

        try {
            CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(key);
            CryptoPP::StringSink *ss = new CryptoPP::StringSink(plaintext);
            CryptoPP::PK_DecryptorFilter *df = new CryptoPP::PK_DecryptorFilter(prng, decryptor, ss);
            CryptoPP::StringSource(this->data, true, df);

            this->data = plaintext;

            return true;
        } catch(const CryptoPP::Exception& e) {

            return false;
        }
    }

    /**
     * Sign the message with RSA PKCS1v1.5 SHA, using the sender id, message timestamp,
     * topic name, topic data and possibly the encryption IV as payload data
     * @param CryptoPP::RSA::PrivateKey key the RSa private key
     */
    void Message::sign(CryptoPP::RSA::PrivateKey key)
    {
        this->signature.clear();
        CryptoPP::AutoSeededRandomPool prng;

        CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(key);
        CryptoPP::StringSink *ss = new CryptoPP::StringSink(this->signature);
        CryptoPP::SignerFilter *sf = new CryptoPP::SignerFilter(prng, signer, ss);

        CryptoPP::StringSource(this->getPayloadData(), true, sf);
    }

    /**
     * Verify the message using the RSA signature value  with RSA PKCS1v1.5 SHA
     * @param  CryptoPP::RSA::PublicKey key the RSA public key
     * @return bool true if verification was successful
     */
    bool Message::verify(CryptoPP::RSA::PublicKey key)
    {
        try {
            CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(key);
            const int flags = CryptoPP::SignatureVerificationFilter::THROW_EXCEPTION;
            CryptoPP::SignatureVerificationFilter *svf = new CryptoPP::SignatureVerificationFilter(verifier, NULL, flags);
            CryptoPP::StringSource(this->getPayloadData() + this->signature, true, svf);

            return true;
        } catch(const CryptoPP::Exception& e) {

            return false;
        }
    }

    /**
     * Generate a random IV of length 'length', the result is stored in the
     * class attribute iv as a CryptoPP::SecByteBlock
     * @param int length the length of the IV
     */
    void Message::generateIV(int length)
    {
        CryptoPP::AutoSeededRandomPool prng;
        this->iv = CryptoPP::SecByteBlock(length);
        prng.GenerateBlock(this->iv, length);
    }

    /**
     * Concatenate the message payload data (the sender id, message timestamp,
     * topic name, topic data and possibly the encryption IV)
     * and return the resulting string for signing purposes
     * @return string payload
     */
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

    /**
     * Apply a CryptoPP::StreamTransformation to the message data
     * @param  CryptoPP::StreamTransformation t
     * @return string the resulting plain- or ciphertext
     */
    std::string Message::applyCipher(CryptoPP::StreamTransformation &t)
    {
        std::string result;
        CryptoPP::StringSink* sink = new CryptoPP::StringSink(result);
        CryptoPP::StreamTransformationFilter* enc = new CryptoPP::StreamTransformationFilter(t, sink);
        CryptoPP::StringSource(this->data, true, enc);
        return result;
    }

    /**
     * Overload << operator, to format the content of a message
     * in an output stream. Shows the message data, sender id,
     * topic name and message timestamp
     */
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

