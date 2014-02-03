
#include "TopicKeyPair.hpp"

namespace cdax {

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
    bytestring TopicKeyPair::getEncKey()
    {
        return this->encryptionKey;
    }

    /**
     * Get the authentication key
     * @return bytestring authentication key
     */
    bytestring TopicKeyPair::getAuthKey()
    {
        return this->authenticationKey;
    }
}
