package cdax;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;

import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;

import javacard.security.AESKey;
import javacard.security.HMACKey;
import javacard.security.KeyPair;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;
import javacard.security.RandomData;


public class ClientApplet extends Applet implements ExtendedLength
{
    private static final byte CDAX_CLA = (byte) 0x80;

    private static final byte GEN_KEYPAIR = (byte) 0x01;
    private static final byte STORE_MASTER = (byte) 0x02;
    private static final byte STORE_KEY = (byte) 0x03;
    private static final byte TEST_SEND = (byte) 0x05;
    private static final byte TEST_RECEIVE = (byte) 0x06;

    private static final byte STORE_TOPIC_KEY = (byte) 0x07;
    private static final byte ENCODE = (byte) 0x08;
    private static final byte DECODE = (byte) 0x09;

    private static final byte RSA_SIGN = (byte) 0x10;
    private static final byte RSA_VERIFY = (byte) 0x11;
    private static final byte RSA_ENC = (byte) 0x12;
    private static final byte RSA_DEC = (byte) 0x13;
    private static final byte HMAC_SIGN = (byte) 0x20;
    private static final byte HMAC_VERIFY = (byte) 0x21;
    private static final byte AES_ENC = (byte) 0x30;
    private static final byte AES_DEC = (byte) 0x31;

    private static final short ZERO = 0;
    private static final short ONE = 1;

    private static final short HEADER_LEN = 7;

    // aes constants
    private static final short AES_BLOCK_SIZE = 16;
    private static final short AES_KEY_SIZE = 16;

    // hmac constants
    private static final short HMAC_BLOCK_SIZE = 64;
    private static final short HMAC_KEY_SIZE = 128;

    // rsa key length in bytes
    private static final short RSA_CRT_PARAM_LEN = 128;
    private static final short RSA_MOD_LEN = 256;
    private static final short RSA_EXP_LEN = 3;
    private static final short RSA_SIGN_LEN = 256;

    // server public key
    private RSAPublicKey masterKey;

    // topic key count
    private static final short TOPIC_KEY_COUNT = 2;

    // private HMACKey hmacKey;
    private byte[] hmacKey;
    private byte[] aesKey;

    // client RSA key pair
    private KeyPair keyPair;

    private Cipher rsaCipher;
    private Cipher aesCipher;

    private RandomData random;

    public ClientApplet()
    {
        this.register();
        this.masterKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048,false);
        this.hmacKey = new byte[(short) (HMAC_KEY_SIZE * TOPIC_KEY_COUNT)];
        this.aesKey = new byte[(short) (AES_KEY_SIZE * TOPIC_KEY_COUNT)];
        this.keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
        this.rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        this.aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        this.random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }

    public static void install(byte[] buffer, short offset, byte length)
    {
        new ClientApplet();
    }

    public void process(APDU apdu)
    {
        byte[] buffer = apdu.getBuffer();

        if (apdu.isISOInterindustryCLA()) {
            if (this.selectingApplet()) {
                return;
            } else {
                ISOException.throwIt (ISO7816.SW_CLA_NOT_SUPPORTED);
            }
        }

        byte P1  = (byte) (buffer[ISO7816.OFFSET_P1] & 0xFF);
        byte P2  = (byte) (buffer[ISO7816.OFFSET_P2] & 0xFF);
        byte LC  = (byte) (buffer[ISO7816.OFFSET_LC] & 0xFF);

        if (buffer[ISO7816.OFFSET_CLA] != CDAX_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        short LEN = (short) (LC & 0xFF);

        if (LEN == 0) {
            LEN = Util.getShort(buffer, (short) (ISO7816.OFFSET_LC + ONE));
        }

        switch (buffer[ISO7816.OFFSET_INS] & 0xFF) {
            case GEN_KEYPAIR:
                apdu.setOutgoingAndSend(ZERO, this.generate_keyPair(buffer));
                break;
            case STORE_MASTER:
                this.store_master(buffer, HEADER_LEN);
                apdu.setOutgoing();
                break;
            case STORE_TOPIC_KEY:
                this.store_topic_key(buffer, HEADER_LEN, LEN, P1);
                apdu.setOutgoing();
                break;
            case STORE_KEY:
                this.store_key(buffer, HEADER_LEN, LEN, P1);
                apdu.setOutgoingAndSend(HEADER_LEN, LEN);
                break;
            case RSA_SIGN:
                apdu.setOutgoingAndSend(ZERO, this.rsa_sign(buffer, HEADER_LEN, LEN));
                break;
            case RSA_VERIFY:
                buffer[0] = this.rsa_verify(buffer, HEADER_LEN, LEN);
                apdu.setOutgoingAndSend(ZERO, ONE);
                break;
            case RSA_ENC:
                apdu.setOutgoingAndSend(ZERO, this.rsa_encrypt(buffer, HEADER_LEN, LEN));
                break;
            case RSA_DEC:
                apdu.setOutgoingAndSend(ZERO, this.rsa_decrypt(buffer, HEADER_LEN, LEN));
                break;
            case HMAC_SIGN:
                this.hmac(buffer, HEADER_LEN, LEN, P1);
                apdu.setOutgoingAndSend(ZERO, MessageDigest.LENGTH_SHA_256);
                break;
            case HMAC_VERIFY:
                buffer[0] = this.verify_hmac(buffer, HEADER_LEN, LEN, P1);
                apdu.setOutgoingAndSend(ZERO, ONE);
                break;
            case AES_ENC:
                apdu.setOutgoingAndSend(ZERO, this.aes_encrypt(buffer, HEADER_LEN, LEN, P1, P2));
                break;
            case AES_DEC:
                apdu.setOutgoingAndSend(ZERO, this.aes_decrypt(buffer, HEADER_LEN, LEN, P1, P2));
                break;
            case TEST_SEND:
                apdu.setOutgoingAndSend(ZERO, ZERO);
            case TEST_RECEIVE:
                apdu.setOutgoingAndSend(ZERO, Util.getShort(buffer, ISO7816.OFFSET_P1));
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void store_topic_key(byte[] buffer, short offset, short length, short p1)
    {
        short data_len = Util.getShort(buffer, offset);
        offset += (short) 2;
        Signature rsa_ver = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        rsa_ver.init(this.masterKey, Signature.MODE_VERIFY);
        short rsa_data_len = (short) (length - RSA_SIGN_LEN - 2);
        if (!rsa_ver.verify(buffer, offset, rsa_data_len, buffer, (short) (offset + rsa_data_len), RSA_SIGN_LEN)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        offset = (short) (offset + rsa_data_len - data_len);
        rsaCipher.init(this.keyPair.getPrivate(), Cipher.MODE_DECRYPT);
        short len = rsaCipher.doFinal(buffer, offset, data_len, buffer, ZERO);
        this.store_key(buffer, ZERO, len, p1);
    }

    private short generate_keyPair(byte[] buffer)
    {
        this.keyPair.genKeyPair();
        RSAPublicKey pub = (RSAPublicKey) this.keyPair.getPublic();
        pub.getModulus(buffer, ZERO);
        pub.getExponent(buffer, RSA_MOD_LEN);
        return (short) (RSA_MOD_LEN + RSA_EXP_LEN);
    }

    private void store_master(byte[] buffer, short offset)
    {
        this.masterKey.setModulus(buffer, offset, RSA_MOD_LEN);
        this.masterKey.setExponent(buffer, (short) (offset + RSA_MOD_LEN), RSA_EXP_LEN);
    }

    private void store_key(byte[] buffer, short offset, short length, short p1)
    {
        Util.arrayCopyNonAtomic(buffer, offset, this.aesKey, (short) (AES_KEY_SIZE * p1), length);
        offset += AES_KEY_SIZE;
        // crate hmac keys
        for (short i = ZERO; i < length; i++) {
            this.hmacKey[(short) (HMAC_KEY_SIZE * p1 + i)] = (byte) (buffer[(short) (offset + i)] ^ 0x36);
        }
        Util.arrayFillNonAtomic(this.hmacKey, (short) (HMAC_KEY_SIZE * p1 + length), (short) (HMAC_BLOCK_SIZE - length), (byte) 0x36);
        for (short i = HMAC_BLOCK_SIZE; i < (short) (HMAC_BLOCK_SIZE + length); i++) {
            this.hmacKey[(short) (HMAC_KEY_SIZE * p1 + i)] = (byte) (buffer[(short) (offset + i - HMAC_BLOCK_SIZE)] ^ 0x5C);
        }
        Util.arrayFillNonAtomic(this.hmacKey, (short) (HMAC_KEY_SIZE * p1 + HMAC_BLOCK_SIZE + length), (short) (HMAC_BLOCK_SIZE - length), (byte) 0x5C);
    }

    private short rsa_sign(byte[] buffer, short offset, short length)
    {
        Signature rsa_sig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        rsa_sig.init(this.keyPair.getPrivate(), Signature.MODE_SIGN);
        return rsa_sig.sign(buffer, offset, length, buffer, ZERO);
    }

    private byte rsa_verify(byte[] buffer, short offset, short length)
    {
        Signature rsa_ver = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        rsa_ver.init(this.masterKey, Signature.MODE_VERIFY);
        short rsa_data_len = (short) (length - RSA_SIGN_LEN - offset);
        if (rsa_ver.verify(buffer, offset, rsa_data_len, buffer, (short) (length - RSA_SIGN_LEN), RSA_SIGN_LEN)) {
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

    private short aes_encrypt(byte[] buffer, short offset, short length, byte p1, byte p2)
    {
        short len;

        if ((p2 & 0x0F) == 0x01) {
            // add pkcs7 padding
            byte padding = (byte) (AES_BLOCK_SIZE - (length % AES_BLOCK_SIZE));
            Util.arrayFillNonAtomic(buffer, (short) (HEADER_LEN + length), (short) padding, padding);
            length += padding;
        }

        AESKey key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        key.setKey(this.aesKey, (short) (AES_KEY_SIZE * p1));

        if ((p2 & 0xF0) == 0x10) {
            byte[] iv = JCSystem.makeTransientByteArray(AES_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
            this.random.generateData(iv, ZERO, AES_BLOCK_SIZE);
            this.aesCipher.init(key, Cipher.MODE_ENCRYPT, iv, ZERO, AES_BLOCK_SIZE);
            len = aesCipher.doFinal(buffer, offset, length, buffer, AES_BLOCK_SIZE);
            Util.arrayCopyNonAtomic(iv, ZERO, buffer, ZERO, AES_BLOCK_SIZE);
            // correct output size
            len += AES_BLOCK_SIZE;
        } else {
            this.aesCipher.init(key, Cipher.MODE_ENCRYPT, buffer, offset, AES_BLOCK_SIZE);
            len = aesCipher.doFinal(buffer, (short) (offset + AES_BLOCK_SIZE), length, buffer, ZERO);
            // correct output size
            len -= AES_BLOCK_SIZE;
        }

        key.clearKey();

        return len;
    }

    private short aes_decrypt(byte[] buffer, short offset, short length, byte p1, byte p2)
    {
        AESKey key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        key.setKey(this.aesKey, (short) (AES_KEY_SIZE * p1));

        this.aesCipher.init(key, Cipher.MODE_DECRYPT, buffer, offset, AES_BLOCK_SIZE);
        short len = aesCipher.doFinal(buffer, (short) (offset + AES_BLOCK_SIZE), length, buffer, ZERO);

        key.clearKey();

        if ((p2 & 0x0F) == 0x01) {
            // pkcs7 padding
            byte padding = buffer[(short) (len - ONE)];
            len -= padding;
        }

        // correct output size
        len -= AES_BLOCK_SIZE;

        return len;
    }


    private byte verify_hmac(byte[] buffer, short offset, short length, short p1)
    {
        // store current hmac
        byte[] mac = JCSystem.makeTransientByteArray(MessageDigest.LENGTH_SHA_256, JCSystem.CLEAR_ON_DESELECT);
        short hmac_offset = (short) (offset + length - MessageDigest.LENGTH_SHA_256);
        Util.arrayCopyNonAtomic(buffer, hmac_offset, mac, ZERO, MessageDigest.LENGTH_SHA_256);
        // calculate new hmac
        this.hmac(buffer, offset, (short) (length - MessageDigest.LENGTH_SHA_256), p1);
        // compare the hmac's
        return Util.arrayCompare(buffer, ZERO, mac, ZERO, MessageDigest.LENGTH_SHA_256);
    }

    private void hmac(byte[] buffer, short offset, short length, short p1)
    {
        // H(K XOR opad, H(K XOR ipad, text)
        byte[] inner = JCSystem.makeTransientByteArray((short) (HMAC_BLOCK_SIZE + length), JCSystem.CLEAR_ON_DESELECT);
        byte[] outer = JCSystem.makeTransientByteArray((short) (HMAC_BLOCK_SIZE + MessageDigest.LENGTH_SHA_256), JCSystem.CLEAR_ON_DESELECT);
        // create hmac
        MessageDigest m_sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        Util.arrayCopyNonAtomic(this.hmacKey, (short) (HMAC_KEY_SIZE * p1), inner, ZERO, HMAC_BLOCK_SIZE);
        Util.arrayCopyNonAtomic(buffer, offset, inner, HMAC_BLOCK_SIZE, length);
        m_sha256.doFinal(inner, ZERO, (short) inner.length, outer, HMAC_BLOCK_SIZE);
        Util.arrayCopyNonAtomic(this.hmacKey, (short) (HMAC_KEY_SIZE * p1 + HMAC_BLOCK_SIZE), outer, ZERO, HMAC_BLOCK_SIZE);
        m_sha256.doFinal(outer, ZERO, (short) outer.length, buffer, ZERO);
    }

}
