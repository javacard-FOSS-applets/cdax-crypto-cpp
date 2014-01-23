
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

    void Message::decode(std::string encoded)
    {
        // decode fields based on length in header
        size_t offset = 4;
        this->setId(encoded.substr(offset, encoded[0] & 0xFF));
        offset += encoded[0] & 0xFF;
        this->setTopic(encoded.substr(offset, encoded[1] & 0xFF));
        offset += encoded[1] & 0xFF;
        this->setTimestamp(encoded.substr(offset, encoded[2] & 0xFF));
        offset += encoded[2] & 0xFF;
        this->setSignature(encoded.substr(offset, encoded[3] & 0xFF));
        offset += encoded[3] & 0xFF;
        this->setData(encoded.substr(offset, encoded.size() - offset));
    }

    const std::string Message::encode() const
    {
        bytestring buffer(4);

        // create header with field lengths
        bytestring message_timestamp = this->getTimestamp();
        buffer[0] = this->id.size();
        buffer[1] = this->topic.size();
        buffer[2] = message_timestamp.size();
        buffer[3] = this->signature.size();

        // assign fields
        buffer += this->id;
        buffer += this->topic;
        buffer += message_timestamp;
        buffer += this->signature;
        buffer += this->data;

        return buffer.str();
    }

    const bytestring Message::getPayload() const
    {
        bytestring buffer;

        // assign fields
        buffer += this->id;
        buffer += this->topic;
        buffer += this->getTimestamp();
        buffer += this->data;

        return buffer;
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
     * Get the sender identity
     * @return string identity
     */
    bytestring Message::getId() const
    {
        return this->id;
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
    bytestring Message::getTopic() const
    {
        return this->topic;
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
    bytestring Message::getData() const
    {
        return this->data;
    }

    void Message::setTimestamp(bytestring message_timestamp)
    {
        this->timestamp = 0;
        size_t size = message_timestamp.size();
        for (int i = 0; i < size; i++) {
            this->timestamp = (this->timestamp << 8) | (message_timestamp[i] & 0xFF);
        }
    }

    // convert timestamp (64 bit uint) to byte array
    bytestring Message::getTimestamp() const
    {
        size_t time_len = sizeof(this->timestamp);
        bytestring message_timestamp(time_len);
        for (int i = 0; i < time_len; i++) {
            message_timestamp[time_len - 1 - i] = (this->timestamp >> (i * 8)) & 0xFF;
        }
        return message_timestamp;
    }

    /**
     * Set the message signature or HMAC code as a string
     * @param bytestring signature value
     */
    void Message::setSignature(bytestring sig)
    {
        this->signature = sig;
    }

    /**
     * Get the message signature or HMAC code as a string
     * @return string HMAC or RSA signature
     */
    bytestring Message::getSignature() const
    {
        return this->signature;
    }

    /**
     * Encrypt the message topic data using AES CBC and a fresh random IV
     * @param bytestring key encryption key
     */
    void Message::aesEncrypt(bytestring* key)
    {
        bytestring iv = this->generateIV(CryptoPP::AES::BLOCKSIZE);
        std::string ciphertext;
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encrypt(key->BytePtr(), key->size(), iv);
        CryptoPP::StringSink *ss = new CryptoPP::StringSink(ciphertext);
        CryptoPP::StreamTransformationFilter* enc = new CryptoPP::StreamTransformationFilter(encrypt, ss);
        CryptoPP::StringSource(this->data.str(), true, enc);
        this->data = ciphertext;
        this->data.Assign(iv + this->data);
    }

    /**
     * Decrypt the AES CBC encrypted message payload
     * This requires the correct IV attribute to be set.
     * @param  bytestring key AES key
     * @return bool true if decryption was successful
     */
    bool Message::aesDecrypt(bytestring* key)
    {
        try {
            std::string plaintext;
            bytestring iv = this->data.str().substr(0, CryptoPP::AES::BLOCKSIZE);
            bytestring ciphertext = this->data.str().substr(CryptoPP::AES::BLOCKSIZE);
            CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decrypt(key->BytePtr(), key->size(), iv);
            CryptoPP::StringSink *ss = new CryptoPP::StringSink(plaintext);
            CryptoPP::StreamTransformationFilter* enc = new CryptoPP::StreamTransformationFilter(decrypt, ss);
            CryptoPP::StringSource(ciphertext.str(), true, enc);
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
        CryptoPP::StringSource(this->getPayload().str(), true, hf);
        this->signature = sig;
    }

    /**
     * Verify the message HMAC
     * @param  bytestring key HMAC key
     * @return bool true if the verification was successful
     */
    bool Message::hmacVerify(bytestring* key)
    {
        try {
            CryptoPP::HMAC<CryptoPP::SHA256> hmac(key->BytePtr(), key->size());
            const int flags = CryptoPP::HashVerificationFilter::THROW_EXCEPTION | CryptoPP::HashVerificationFilter::HASH_AT_END;
            CryptoPP::HashVerificationFilter *hvf = new CryptoPP::HashVerificationFilter(hmac, NULL, flags);
            CryptoPP::StringSource(this->getPayload().str() + this->signature.str(), true, hvf);
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
        CryptoPP::StringSource(this->getPayload().str(), true, sf);

        this->signature = sig;
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
            CryptoPP::StringSource(this->getPayload().str() + this->signature.str(), true, svf);

            return true;
        } catch(const CryptoPP::Exception& e) {

            return false;
        }
    }

    bool Message::sign(SmartCard* card)
    {
        bytestring buffer = this->getPayload();
        if (!card->sign(buffer)) {
            return false;
        }
        this->signature = buffer;

        return true;
    }

    bool Message::verify(SmartCard* card)
    {
        bytestring buffer = this->getPayload();
        buffer.Assign(buffer + this->signature);
        return card->verify(buffer);
    }

    bool Message::encrypt(SmartCard* card)
    {
        return card->encrypt(this->data);
    }

    bool Message::decrypt(SmartCard* card)
    {
        return card->decrypt(this->data);
    }

    bool Message::aesEncrypt(SmartCard* card)
    {
        // add pkcs7 padding
        size_t size = this->data.size();
        size_t padding = CryptoPP::AES::BLOCKSIZE - (size % CryptoPP::AES::BLOCKSIZE);
        this->data.resize(size + padding);
        for (int i = size; i < size + padding; i++) {
            this->data[i] = padding;
        }

        if (!card->aesDecrypt(this->data)) {
            return false;
        }

        return true;
    }

    bool Message::aesDecrypt(SmartCard* card)
    {
        bytestring buffer = this->data;
        if (!card->aesDecrypt(this->data)) {
            return false;
        }

        // remove pkcs7 padding
        size_t len = this->data.size();
        this->data.resize(len - (this->data[len - 1] & 0xFF));

        return true;
    }

    bool Message::hmac(SmartCard* card)
    {
        bytestring buffer = this->getPayload();
        if (!card->hmac(buffer)) {
            return false;
        }
        this->signature = buffer;

        return true;
    }

    bool Message::hmacVerify(SmartCard* card)
    {
        bytestring buffer = this->getPayload();
        buffer.Assign(buffer + this->signature);
        return card->hmacVerify(buffer);
    }

    /**
     * Generate a random IV of length 'length', the result is stored in the
     * class attribute iv as a bytestring
     * @param int length the length of the IV
     */
    bytestring Message::generateIV(int length) const
    {
        CryptoPP::AutoSeededRandomPool prng;
        bytestring iv = bytestring(length);
        prng.GenerateBlock(iv, length);
        return iv;
    }

    /**
     * Overload << operator, to format the content of a message
     * in an output stream. Shows the message data, sender id,
     * topic name and message timestamp
     */
    std::ostream &operator<< (std::ostream &out, const Message &msg)
    {
        out << "data: " << hex(msg.data) << std::endl;
        out << "topic: " << msg.topic << std::endl;
        out << "source: " << msg.id << std::endl;
        if (msg.signature.size() > 0) {
            out << "hmac/signature: " << hex(msg.signature) << std::endl;
        }
        out << "time: " << std::ctime(&msg.timestamp);

        return out;
    }
}

