package cdax;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.CardRuntimeException;


import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;

import javacard.security.AESKey;
import javacard.security.HMACKey;
import javacard.security.KeyPair;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacard.security.CryptoException;

import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;

import javacard.security.ECPublicKey;
import javacard.security.ECPrivateKey;

import javacard.security.CryptoException;
import javacard.security.MessageDigest;
import javacard.security.RandomData;


public class ClientApplet extends Applet implements ExtendedLength
{
    private static final byte CDAX_CLA = (byte) 0x80;

    private static final byte GEN_KEYPAIR = (byte) 0x01;
    private static final byte STORE_MASTER = (byte) 0x02;
    private static final byte CREATE_TOPIC_JOIN = (byte) 0x04;
    private static final byte STORE_TOPIC_KEY = (byte) 0x07;

    private static final byte ENCODE = (byte) 0x08;
    private static final byte DECODE = (byte) 0x09;

    private static final byte RSA_SIGN = (byte) 0x10;
    private static final byte RSA_VERIFY = (byte) 0x11;
    private static final byte RSA_ENC = (byte) 0x12;
    private static final byte RSA_DEC = (byte) 0x13;

    private static final byte STORE_KEY = (byte) 0x03;

    private static final byte HMAC_SIGN = (byte) 0x20;
    private static final byte HMAC_VERIFY = (byte) 0x21;
    private static final byte AES_ENC = (byte) 0x30;
    private static final byte AES_DEC = (byte) 0x31;

    private static final byte TEST_SEND = (byte) 0x05;
    private static final byte TEST_RECEIVE = (byte) 0x06;

    private static final short ZERO = 0;
    private static final short ONE = 1;

    private static final short HEADER_LEN = 7;

    // aes constants
    private static final short AES_BLOCK_SIZE = 16;
    private static final short AES_KEY_SIZE = 16;

    // hmac constants
    private static final short HMAC_BLOCK_SIZE = 64;
    private static final short HMAC_KEY_SIZE = 16;
    private static final short HMAC_KEY_LENGTH = 128;
    private static final short HMAC_BUFFER_SIZE = 1536;

    // rsa key length in bytes
    private static final short RSA_CRT_PARAM_LEN = 128;
    private static final short RSA_MOD_LEN = 256;
    private static final short RSA_EXP_LEN = 3;
    private static final short RSA_SIGN_LEN = 256;

    // server public key
    private RSAPublicKey masterKey;

    // topic key count
    private static final short TOPIC_KEY_COUNT = 32;

    // private HMACKey hmacKeys;
    private byte[] hmacKeys;
    private byte[] aesKeys;
    private AESKey aesKey;

    // temp hmac value array
    private byte[] hmacBuffer;

    // client RSA key pair
    private KeyPair keyPair;
    // private KeyPair eccKeyPair;
    private Signature signature;

    private Cipher rsaCipher;
    private Cipher aesCipher;
    private MessageDigest hash;

    private RandomData random;

    public ClientApplet()
    {
        this.register();

        this.masterKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
        this.keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);

        this.signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        this.rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);

        this.aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        this.aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        this.random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        this.hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        this.hmacKeys = new byte[(short) (HMAC_KEY_LENGTH * TOPIC_KEY_COUNT)];
        this.aesKeys = new byte[(short) (AES_KEY_SIZE * TOPIC_KEY_COUNT)];
        this.hmacBuffer = JCSystem.makeTransientByteArray(HMAC_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
    }

    public static void install(byte[] buffer, short offset, byte length)
    {
        new ClientApplet();
    }

    public void process(APDU apdu) throws ISOException
    {
        byte[] buffer = apdu.getBuffer();

        if (this.selectingApplet()) {
            return;
        }

        short P1  = (short) (buffer[ISO7816.OFFSET_P1] & 0xFF);
        short P2  = (short) (buffer[ISO7816.OFFSET_P2] & 0xFF);
        byte LC  = (byte) (buffer[ISO7816.OFFSET_LC] & 0xFF);

        if (buffer[ISO7816.OFFSET_CLA] != CDAX_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        short LEN = (short) (LC & 0xFF);

        if (LEN == 0) {
            LEN = Util.getShort(buffer, (short) (ISO7816.OFFSET_LC + ONE));
        }

        try {
            switch (buffer[ISO7816.OFFSET_INS] & 0xFF)
            {
                // highlevel functions
                case GEN_KEYPAIR:
                    apdu.setOutgoingAndSend(ZERO, this.generate_keyPair(buffer));
                    break;
                case STORE_MASTER:
                    this.store_master(buffer, HEADER_LEN);
                    apdu.setOutgoing();
                    break;
                case CREATE_TOPIC_JOIN:
                    aapdu.setOutgoingAndSend(ZERO, this.rsa_sign(buffer, HEADER_LEN, LEN));
                    break;
                case STORE_TOPIC_KEY:
                    this.store_topic_key(buffer, HEADER_LEN, LEN);
                    this.store_key(buffer, ZERO, P1);
                    apdu.setOutgoing();
                    break;
                case ENCODE:
                    this.encode(apdu, buffer, HEADER_LEN, LEN, P1);
                    break;
                case DECODE:
                    this.decode(apdu, buffer, HEADER_LEN, LEN, P1);
                    break;

                // crypto tests
                case RSA_SIGN:
                    if (P2 == 1) {
                        this.rsa_sign(buffer, HEADER_LEN, LEN);
                    }
                    apdu.setOutgoingAndSend(ZERO, this.rsa_sign(buffer, HEADER_LEN, LEN));
                    break;
                case RSA_VERIFY:
                    if (P2 == 1) {
                        this.rsa_verify(buffer, HEADER_LEN, LEN);
                    }
                    buffer[0] = this.rsa_verify(buffer, HEADER_LEN, LEN);
                    apdu.setOutgoingAndSend(ZERO, ONE);
                    break;
                case RSA_ENC:
                    if (P2 == 1) {
                        this.rsa_encrypt(buffer, HEADER_LEN, LEN);
                    }
                    apdu.setOutgoingAndSend(ZERO, this.rsa_encrypt(buffer, HEADER_LEN, LEN));
                    break;
                case RSA_DEC:
                    if (P2 == 1) {
                        this.rsa_decrypt(buffer, HEADER_LEN, LEN);
                    }
                    apdu.setOutgoingAndSend(ZERO, this.rsa_decrypt(buffer, HEADER_LEN, LEN));
                    break;

                case STORE_KEY:
                    this.store_key(buffer, HEADER_LEN, P1);
                    apdu.setOutgoingAndSend(HEADER_LEN, LEN);
                    break;
                case HMAC_SIGN:
                    if (P2 == 1) {
                        this.hmac(buffer, HEADER_LEN, LEN, P1, buffer, ZERO);
                    }
                    this.hmac(buffer, HEADER_LEN, LEN, P1, buffer, ZERO);
                    apdu.setOutgoingAndSend(ZERO, MessageDigest.LENGTH_SHA_256);
                    break;
                case HMAC_VERIFY:
                    if (P2 == 1) {
                        this.verify_hmac(buffer, HEADER_LEN, LEN, P1);
                    }
                    buffer[0] = this.verify_hmac(buffer, HEADER_LEN, LEN, P1);
                    apdu.setOutgoingAndSend(ZERO, ONE);
                    break;
                case AES_ENC:
                    if (P2 == 1) {
                        this.aes_encrypt(buffer, HEADER_LEN, LEN, P1, ZERO, ZERO);
                    }
                    apdu.setOutgoingAndSend(ZERO, this.aes_encrypt(buffer, HEADER_LEN, LEN, P1, ZERO, ZERO));
                    break;
                case AES_DEC:
                    if (P2 == 1) {
                        this.aes_decrypt(buffer, HEADER_LEN, LEN, P1, ZERO);
                    }
                    apdu.setOutgoingAndSend(ZERO, this.aes_decrypt(buffer, HEADER_LEN, LEN, P1, ZERO));
                    break;

                // troughput tests
                case TEST_SEND:
                    apdu.setOutgoingAndSend(ZERO, ZERO);
                    break;
                case TEST_RECEIVE:
                    apdu.setOutgoingAndSend(ZERO, Util.getShort(buffer, ISO7816.OFFSET_P1));
                    break;

                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (CardRuntimeException exception) {
            Util.setShort(buffer, ZERO, exception.getReason());
            apdu.setOutgoingAndSend(ZERO, (short) 2);
        }
    }

    private short store_topic_key(byte[] buffer, short offset, short length)
    {
        short data_len = Util.getShort(buffer, offset);
        offset += (short) 2;
        this.signature.init(this.masterKey, Signature.MODE_VERIFY);
        short rsa_data_len = (short) (length - RSA_SIGN_LEN - 2);
        if (!this.signature.verify(buffer, offset, rsa_data_len, buffer, (short) (offset + rsa_data_len), RSA_SIGN_LEN)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        offset = (short) (offset + rsa_data_len - data_len);
        rsaCipher.init(this.keyPair.getPrivate(), Cipher.MODE_DECRYPT);
        return rsaCipher.doFinal(buffer, offset, data_len, buffer, ZERO);
    }

    private short generate_keyPair(byte[] buffer)
    {
        if (!this.keyPair.getPublic().isInitialized()) {
            this.keyPair.genKeyPair();
            RSAPublicKey pub = (RSAPublicKey) this.keyPair.getPublic();
            pub.getModulus(buffer, ZERO);
            pub.getExponent(buffer, RSA_MOD_LEN);
            return (short) (RSA_MOD_LEN + RSA_EXP_LEN);
        }
    }

    private void store_master(byte[] buffer, short offset)
    {
        if (!this.masterKey.isInitialized()) {
            this.masterKey.setModulus(buffer, offset, RSA_MOD_LEN);
            this.masterKey.setExponent(buffer, (short) (offset + RSA_MOD_LEN), RSA_EXP_LEN);
        }
    }

    private void store_key(byte[] buffer, short offset, short key_index)
    {
        Util.arrayCopyNonAtomic(buffer, offset, this.aesKeys, (short) (AES_KEY_SIZE * key_index), AES_KEY_SIZE);
        offset += AES_KEY_SIZE;
        // crate hmac keys
        for (short i = ZERO; i < HMAC_KEY_SIZE; i++) {
            this.hmacKeys[(short) (HMAC_KEY_LENGTH * key_index + i)] = (byte) (buffer[(short) (offset + i)] ^ 0x36);
        }
        Util.arrayFillNonAtomic(this.hmacKeys, (short) (HMAC_KEY_LENGTH * key_index + HMAC_KEY_SIZE), (short) (HMAC_BLOCK_SIZE - HMAC_KEY_SIZE), (byte) 0x36);
        for (short i = HMAC_BLOCK_SIZE; i < (short) (HMAC_BLOCK_SIZE + HMAC_KEY_SIZE); i++) {
            this.hmacKeys[(short) (HMAC_KEY_LENGTH * key_index + i)] = (byte) (buffer[(short) (offset + i - HMAC_BLOCK_SIZE)] ^ 0x5C);
        }
        Util.arrayFillNonAtomic(this.hmacKeys, (short) (HMAC_KEY_LENGTH * key_index + HMAC_BLOCK_SIZE + HMAC_KEY_SIZE), (short) (HMAC_BLOCK_SIZE - HMAC_KEY_SIZE), (byte) 0x5C);
    }

    private void encode(APDU apdu, byte[] buffer, short offset, short length, short key_index)
    {
        // length of the topic data to be encrypted
        short data_len = Util.getShort(buffer, offset);
        // offset in buffer of the topic data to be encrypted
        short data_offset = (short) (offset + length - data_len);
        // encrypt the topic data using aes cbc, the result is put in the same buffer at the original offset
        short cipher_len = this.aes_encrypt(buffer, data_offset, data_len, key_index, ZERO, data_offset);
        // calculate the position after the ecnrypted topic data, at which the hmac has to be appended
        short hmac_offset = (short) (data_offset + cipher_len);
        // calculate to total length of the data over which the hmac will be generated
        short payload_len = (short) (length - data_len - 2 + cipher_len);
        // calculate hmac over the payload (message meta data + topic data)
        this.hmac(buffer, (short) (offset + 2), payload_len, key_index, buffer, hmac_offset);
        // calculate length of aes encrypted data + the length of the hmac
        short encoded_len = (short) (cipher_len + MessageDigest.LENGTH_SHA_256);
        // return the encrypted data with the appended 32 byte hmac
        apdu.setOutgoingAndSend(data_offset, encoded_len);
    }

    private void decode(APDU apdu, byte[] buffer, short offset, short length, short key_index)
    {
        // length of the topic data to be decrypted
        short data_len = Util.getShort(buffer, offset);
        // verify the hmac on the end of the APDU
        byte result = this.verify_hmac(buffer, (short) (offset + 2), (short) (length - 2), key_index);
        // throw exception when hmac is not valid
        if (result != 0x00) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        // calcute the offset of the encrypted data
        short data_offset = (short) (offset + length - MessageDigest.LENGTH_SHA_256 - data_len);
        // aes cbc decrypt the encrypted topic data, return the length of the plaintext (+padding)
        short plain_len = this.aes_decrypt(buffer, data_offset, data_len, key_index, ZERO);
        // resturn the plaintext+padding
        apdu.setOutgoingAndSend(ZERO, plain_len);
    }

    private short rsa_sign(byte[] buffer, short offset, short length) throws CryptoException
    {
        this.signature.init(this.keyPair.getPrivate(), Signature.MODE_SIGN);
        return this.signature.sign(buffer, offset, length, buffer, ZERO);
    }

    private byte rsa_verify(byte[] buffer, short offset, short length) throws CryptoException
    {
        this.signature.init(this.masterKey, Signature.MODE_VERIFY);
        short rsa_data_len = (short) (length - RSA_SIGN_LEN);
        short signature_offset = (short) (offset + length - RSA_SIGN_LEN);
        if (this.signature.verify(buffer, offset, rsa_data_len, buffer, signature_offset, RSA_SIGN_LEN)) {
            return (byte) ZERO;
        }
        return (byte) ONE;
    }

    private short rsa_encrypt(byte[] buffer, short offset, short length)
    {
        rsaCipher.init(this.masterKey, Cipher.MODE_ENCRYPT);
        return rsaCipher.doFinal(buffer, offset, length, buffer, ZERO);
    }

    private short rsa_decrypt(byte[] buffer, short offset, short length)
    {
        rsaCipher.init(this.keyPair.getPrivate(), Cipher.MODE_DECRYPT);
        return rsaCipher.doFinal(buffer, offset, length, buffer, ZERO);
    }

    private short aes_encrypt(byte[] buffer, short offset, short length, short key_index, short flags, short target_offset)
    {
        short len;

        if (flags == 1) {
            // add pkcs7 padding
            byte padding = (byte) (AES_BLOCK_SIZE - (length % AES_BLOCK_SIZE));
            Util.arrayFillNonAtomic(buffer, (short) (HEADER_LEN + length), (short) padding, padding);
            length += padding;
        }

        this.aesKey.setKey(this.aesKeys, (short) (AES_KEY_SIZE * key_index));

        if ((flags & 0xF0) == 0x10) {
            this.aesCipher.init(this.aesKey, Cipher.MODE_ENCRYPT, buffer, offset, AES_BLOCK_SIZE);
            len = aesCipher.doFinal(buffer, (short) (offset + AES_BLOCK_SIZE), length, buffer, target_offset);
            // correct output size
            len -= AES_BLOCK_SIZE;
        } else {
            Util.arrayCopyNonAtomic(buffer, offset, buffer, (short) (target_offset + AES_BLOCK_SIZE), length);
            this.random.generateData(buffer, target_offset, AES_BLOCK_SIZE);
            this.aesCipher.init(this.aesKey, Cipher.MODE_ENCRYPT, buffer, target_offset, AES_BLOCK_SIZE);
            len = aesCipher.doFinal(buffer, (short) (target_offset + AES_BLOCK_SIZE), length, buffer, (short) (target_offset + AES_BLOCK_SIZE));
            // correct output size
            len += AES_BLOCK_SIZE;
        }

        this.aesKey.clearKey();

        return len;
    }

    private short aes_decrypt(byte[] buffer, short offset, short length, short key_index, short flags)
    {
        this.aesKey.setKey(this.aesKeys, (short) (AES_KEY_SIZE * key_index));

        this.aesCipher.init(this.aesKey, Cipher.MODE_DECRYPT, buffer, offset, AES_BLOCK_SIZE);
        short len = aesCipher.doFinal(buffer, (short) (offset + AES_BLOCK_SIZE), length, buffer, ZERO);

        this.aesKey.clearKey();

        if (flags == 1) {
            // pkcs7 padding
            byte padding = buffer[(short) (len - ONE)];
            len -= padding;
        }

        // correct output size
        len -= AES_BLOCK_SIZE;

        return len;
    }

    private byte verify_hmac(byte[] buffer, short offset, short length, short key_index)
    {
        // calculate new hmac
        this.hmac(buffer, offset, (short) (length - MessageDigest.LENGTH_SHA_256), key_index, buffer, (short) (offset + length));
        // compare the hmac's
        return Util.arrayCompare(buffer, (short) (offset + length - MessageDigest.LENGTH_SHA_256), buffer, (short) (offset + length), MessageDigest.LENGTH_SHA_256);
    }

    private void hmac(byte[] buffer, short offset, short length, short key_index, byte[] target, short target_offset)
    {
        // place data in hmac buffer, reserve space for ipad
        Util.arrayCopyNonAtomic(buffer, offset, this.hmacBuffer, HMAC_BLOCK_SIZE, length);
        // place ipad in hmac buffer
        Util.arrayCopyNonAtomic(this.hmacKeys, (short) (HMAC_KEY_LENGTH * key_index), this.hmacBuffer, ZERO, HMAC_BLOCK_SIZE);
        // calculate initial hash, reserve space for opad
        this.hash.doFinal(this.hmacBuffer, ZERO, (short) (length + HMAC_BLOCK_SIZE), this.hmacBuffer, HMAC_BLOCK_SIZE);
        // place opad in the buffer
        Util.arrayCopyNonAtomic(this.hmacKeys, (short) (HMAC_KEY_LENGTH * key_index + HMAC_BLOCK_SIZE), this.hmacBuffer, ZERO, HMAC_BLOCK_SIZE);
        // calculate second and final hash
        this.hash.doFinal(this.hmacBuffer, ZERO, (short) (HMAC_BLOCK_SIZE + MessageDigest.LENGTH_SHA_256), target, target_offset);
    }

}
