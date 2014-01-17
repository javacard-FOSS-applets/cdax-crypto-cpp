
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
    Message::Message(bytestring identity, bytestring topic_name, bytestring topic_data)
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
    void Message::setId(bytestring identity)
    {
        this->id = identity;
    }

    /**
     * Get the name of the sender
     * @param string topic_name
     */
    void Message::setTopic(bytestring topic_name)
    {
        this->topic = topic_name;
    }

    /**
     * Get the topic name
     * @return string topic name
     */
    bytestring Message::getTopic()
    {
        return this->topic;
    }

    /**
     * Get the sender identity
     * @return string identity
     */
    bytestring Message::getId()
    {
        return this->id;
    }

    /**
     * Set the message topic data/payload
     * @param string topic_data
     */
    void Message::setData(bytestring topic_data)
    {
        this->data = topic_data;
    }

    /**
     * Get the message topic data/payload
     * @return string topic data
     */
    bytestring Message::getData()
    {
        return this->data;
    }

    /**
     * Get the message signature or HMAC code as a string
     * @return string HMAC or RSA signature
     */
    bytestring Message::getSignature()
    {
        return this->signature;
    }

    /**
     * HMAC and AES encrypt the message using the same key.
     * The HMAC is appended to the message topic data before encrypting
     * @param bytestring key
     */
    void Message::encryptAndHMAC(bytestring* key)
    {
        this->encrypt(key);
        this->hmac(key);
        this->data += this->signature;
        this->signature.clear();
    }

    /**
     * AES decrypt the message and verify the HMAC
     * @param  bytestring key AES and HMAC key
     * @return bool true if decryption and verification are successful
     */
    bool Message::verifyAndDecrypt(bytestring* key)
    {
        this->signature = this->data.str().substr(this->data.size() - 32, 32);
        this->data = this->data.str().substr(0, this->data.size() - 32);

        if (!this->verify(key)) {
            return false;
        }

        return this->decrypt(key);
    }

    /**
     * Encrypt the message topic data using AES CBC and a fresh random IV
     * @param bytestring key encryption key
     */
    void Message::encrypt(bytestring* key)
    {
        generateIV(CryptoPP::AES::BLOCKSIZE);
        std::string ciphertext;
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encrypt(key->BytePtr(), key->size(), this->iv);
        CryptoPP::StringSink *ss = new CryptoPP::StringSink(ciphertext);
        CryptoPP::StreamTransformationFilter* enc = new CryptoPP::StreamTransformationFilter(encrypt, ss);
        CryptoPP::StringSource(this->data.str(), true, enc);
        this->data = ciphertext;
    }

    /**
     * Decrypt the AES CBC encrypted message payload
     * This requires the correct IV attribute to be set.
     * @param  bytestring key AES key
     * @return bool true if decryption was successful
     */
    bool Message::decrypt(bytestring* key)
    {
        try {
            std::string plaintext;
            CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decrypt(key->BytePtr(), key->size(), this->iv);
            CryptoPP::StringSink *ss = new CryptoPP::StringSink(plaintext);
            CryptoPP::StreamTransformationFilter* enc = new CryptoPP::StreamTransformationFilter(decrypt, ss);
            CryptoPP::StringSource(this->data.str(), true, enc);
            // this->iv.clear();
            this->data = plaintext;

            return true;
        } catch(const CryptoPP::Exception& e) {

            return false;
        }
    }

    /**
     * Add HMAC to the message, using the sender id, message timestamp,
     * topic name, topic data and possibly the encryption IV as payload data
     * @param bytestring key HMAC key
     */
    void Message::hmac(bytestring* key)
    {
        std::string sig;
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(key->BytePtr(), key->size());
        CryptoPP::StringSink *ss = new CryptoPP::StringSink(sig);
        CryptoPP::HashFilter *hf = new CryptoPP::HashFilter(hmac, ss);
        CryptoPP::StringSource(this->getPayloadData(), true, hf);
        this->signature = sig;
    }

    /**
     * Verify the message HMAC
     * @param  bytestring key HMAC key
     * @return bool true if the verification was successful
     */
    bool Message::verify(bytestring* key)
    {
        try {
            CryptoPP::HMAC<CryptoPP::SHA256> hmac(key->BytePtr(), key->size());
            const int flags = CryptoPP::HashVerificationFilter::THROW_EXCEPTION | CryptoPP::HashVerificationFilter::HASH_AT_END;
            CryptoPP::HashVerificationFilter *hvf = new CryptoPP::HashVerificationFilter(hmac, NULL, flags);
            CryptoPP::StringSource(this->getPayloadData() + this->signature.str(), true, hvf);

            return true;
        } catch(const CryptoPP::Exception& e) {

            return false;
        }
    }

    /**
     * Encrypt the message payload data with RSA RSAES OAEP SHA
     * @param CryptoPP::RSA::PublicKey key the RSA public key to use
     */
    void Message::encrypt(CryptoPP::RSA::PublicKey* key)
    {
        std::string ciphertext;
        CryptoPP::AutoSeededRandomPool prng;

        CryptoPP::RSAES_PKCS1v15_Encryptor encryptor(*key);
        CryptoPP::StringSink *ss = new CryptoPP::StringSink(ciphertext);
        CryptoPP::PK_EncryptorFilter *ef = new CryptoPP::PK_EncryptorFilter(prng, encryptor, ss);
        CryptoPP::StringSource(this->data.str(), true, ef);

        this->data = ciphertext;
    }

    /**
     * Decrypt the message payload data with RSA RSAES OAEP SHA
     * @param  CryptoPP::RSA::PrivateKey key the private key
     * @return bool true if decryption was successful
     */
    bool Message::decrypt(CryptoPP::RSA::PrivateKey* key)
    {
        std::string plaintext;
        CryptoPP::AutoSeededRandomPool prng;

        try {
            CryptoPP::RSAES_PKCS1v15_Decryptor decryptor(*key);
            CryptoPP::StringSink *ss = new CryptoPP::StringSink(plaintext);
            CryptoPP::PK_DecryptorFilter *df = new CryptoPP::PK_DecryptorFilter(prng, decryptor, ss);
            CryptoPP::StringSource(this->data.str(), true, df);

            this->data = plaintext;

            return true;
        } catch(const CryptoPP::Exception& e) {

            std::cout << e.what() << std::endl;

            return false;
        }
    }

    /**
     * Sign the message with RSA PKCS1v1.5 SHA, using the sender id, message timestamp,
     * topic name, topic data and possibly the encryption IV as payload data
     * @param CryptoPP::RSA::PrivateKey key the RSa private key
     */
    void Message::sign(CryptoPP::RSA::PrivateKey* key)
    {
        std::string sig;
        CryptoPP::AutoSeededRandomPool prng;

        CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(*key);
        CryptoPP::StringSink *ss = new CryptoPP::StringSink(sig);
        CryptoPP::SignerFilter *sf = new CryptoPP::SignerFilter(prng, signer, ss);
        CryptoPP::StringSource(this->getPayloadData(), true, sf);

        this->signature = sig;
    }

    bool Message::signOnCard(SmartCard* card)
    {
        bytestring buffer = this->getPayloadData();
        if (!card->sign(buffer)) {
            return false;
        }
        this->signature = buffer;

        return true;
    }

    bool Message::verifyOnCard(SmartCard* card)
    {
        bytestring buffer = this->getPayloadData();
        buffer.Assign(buffer + this->signature);
        return card->verify(buffer);
    }

    bool Message::encryptOnCard(SmartCard* card)
    {
        return card->encrypt(this->data);
    }

    bool Message::decryptOnCard(SmartCard* card)
    {
        return card->decrypt(this->data);
    }

    bool Message::aesEncryptOnCard(SmartCard* card)
    {
        // add pkcs7 padding
        size_t size = this->data.size();
        size_t padding = CryptoPP::AES::BLOCKSIZE - (size % CryptoPP::AES::BLOCKSIZE);
        this->data.resize(size + padding);
        for (int i = size; i < size + padding; i++) {
            this->data[i] = padding;
        }

        if (!card->encryptAES(this->data)) {
            return false;
        }

        this->iv =  this->data.str().substr(0, CryptoPP::AES::BLOCKSIZE);
        this->data = this->data.str().substr(CryptoPP::AES::BLOCKSIZE, this->data.size() - CryptoPP::AES::BLOCKSIZE);

        return true;
    }

    bool Message::aesDecryptOnCard(SmartCard* card)
    {
        bytestring buffer;
        buffer.Assign(this->iv + this->data);
        if (!card->decryptAES(buffer)) {
            return false;
        }
        // remove pkcs7 padding
        buffer.resize(buffer.size() - buffer[buffer.size() - 1]);
        this->data = buffer;
        return true;
    }

    bool Message::hmacOnCard(SmartCard* card)
    {
        bytestring buffer = this->getPayloadData();
        if (!card->appendHMAC(buffer)) {
            return false;
        }
        this->signature = buffer;

        return true;
    }

    bool Message::verifyHMACOnCard(SmartCard* card)
    {
        bytestring buffer = this->getPayloadData();
        buffer.Assign(buffer + this->signature);
        return card->verifyHMAC(buffer);
    }

    /**
     * Verify the message using the RSA signature value  with RSA PKCS1v1.5 SHA
     * @param  CryptoPP::RSA::PublicKey key the RSA public key
     * @return bool true if verification was successful
     */
    bool Message::verify(CryptoPP::RSA::PublicKey* key)
    {
        try {
            CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(*key);
            const int flags = CryptoPP::SignatureVerificationFilter::THROW_EXCEPTION;
            CryptoPP::SignatureVerificationFilter *svf = new CryptoPP::SignatureVerificationFilter(verifier, NULL, flags);
            CryptoPP::StringSource(this->getPayloadData() + this->signature.str(), true, svf);

            return true;
        } catch(const CryptoPP::Exception& e) {

            return false;
        }
    }

    /**
     * Generate a random IV of length 'length', the result is stored in the
     * class attribute iv as a bytestring
     * @param int length the length of the IV
     */
    void Message::generateIV(int length)
    {
        CryptoPP::AutoSeededRandomPool prng;
        this->iv = bytestring(length);
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
     * Overload << operator, to format the content of a message
     * in an output stream. Shows the message data, sender id,
     * topic name and message timestamp
     */
    std::ostream &operator<< (std::ostream &out, const Message &msg)
    {
        out << "message plain text: " << hex(msg.data);

        if (msg.iv.size() > 0) {
            out << " iv: " << hex(msg.iv);
        }

        out << " topic: " << msg.topic << " source: " << msg.id;
        out << " " << std::ctime(&msg.timestamp);

        if (msg.signature.size() > 0) {
            out << "mac/signature: " << hex(msg.signature) << std::endl;
        }

        return out;
    }
}

