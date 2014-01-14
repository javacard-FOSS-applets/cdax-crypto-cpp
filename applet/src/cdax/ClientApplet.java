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


public class ClientApplet extends Applet implements ExtendedLength
{
    private static final byte CDAX_CLA = (byte) 0x80;

    private static final byte GEN_KEYPAIR = (byte) 0x01;
    private static final byte STORE_MASTER = (byte) 0x02;

    private static final byte STORE_KEY = (byte) 0x03;

    private static final byte RSA_SIGN = (byte) 0x10;
    private static final byte RSA_VERIFY = (byte) 0x11;
    private static final byte RSA_ENC = (byte) 0x12;
    private static final byte RSA_DEC = (byte) 0x13;

    private static final byte HMAC_SIGN = (byte) 0x20;
    private static final byte HMAC_VERIFY = (byte) 0x21;

    private static final byte AES_ENC = (byte) 0x30;
    private static final byte AES_DEC = (byte) 0x31;

    private static final short ZERO = 0;

    private static final short HEADER_LEN = 7;

    // rsa key length in bytes
    private static final short RSA_CRT_PARAM_LEN = 128;
    private static final short RSA_MOD_LEN = 256;
    private static final short RSA_EXP_LEN = 3;
    private static final short RSA_SIGN_LEN = 256;

    // server public key
    private RSAPublicKey masterKey;

    // private HMACKey hmacKey;
    private byte[] hmacKey;
    private AESKey aesKey;

    // client RSA key pair
    private KeyPair keyPair;

    private Cipher rsaCipher;
    private Cipher aesCipher;

    public ClientApplet() {
        this.register();

        this.masterKey = (RSAPublicKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_RSA_PUBLIC,
            KeyBuilder.LENGTH_RSA_2048,
            false
        );

        // this.hmacKey = (HMACKey) KeyBuilder.buildKey(
        //     KeyBuilder.TYPE_HMAC,
        //     KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64,
        //     false
        // );

        this.hmacKey = new byte[128];

        this.aesKey = (AESKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_AES,
            KeyBuilder.LENGTH_AES_128,
            false
        );

        this.keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);

        this.rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        this.aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
    }

    public static void install(byte[] buffer, short offset, byte length) {
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

        byte CLA = (byte) (buffer[ISO7816.OFFSET_CLA] & 0xFF);
        byte INS = (byte) (buffer[ISO7816.OFFSET_INS] & 0xFF);
        byte P1  = (byte) (buffer[ISO7816.OFFSET_P1] & 0xFF);
        byte P2  = (byte) (buffer[ISO7816.OFFSET_P2] & 0xFF);
        byte LC  = (byte) (buffer[ISO7816.OFFSET_LC] & 0xFF);

        if (CLA != CDAX_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        short LEN = (short) (LC & 0xFF);

        if (LEN == 0) {
            LEN = Util.getShort(buffer, (short) (ISO7816.OFFSET_LC + 1));
        }

        switch (INS) {
            case GEN_KEYPAIR:
                this.keyPair.genKeyPair();
                RSAPublicKey pub = (RSAPublicKey) this.keyPair.getPublic();
                pub.getModulus(buffer, ZERO);
                pub.getExponent(buffer, RSA_MOD_LEN);
                apdu.setOutgoingAndSend(ZERO, (short) (RSA_MOD_LEN + RSA_EXP_LEN));
                break;
            case STORE_MASTER:
                this.masterKey.setModulus(buffer, HEADER_LEN, RSA_MOD_LEN);
                this.masterKey.setExponent(buffer, (short) (HEADER_LEN + RSA_MOD_LEN), RSA_EXP_LEN);
                apdu.setOutgoingAndSend(ZERO, ZERO);
                break;
            case STORE_KEY:
                this.aesKey.setKey(buffer, HEADER_LEN);

                // crate hmac keys
                for (short i = 0; i < 16; i++) {
                    this.hmacKey[i] = (byte) (buffer[(short) (HEADER_LEN + i)] ^ 0x36);
                }
                Util.arrayFillNonAtomic(this.hmacKey, (short) 16, (short) 48, (byte) 0x36);

                for (short i = 64; i < 80; i++) {
                    this.hmacKey[i] = (byte) (buffer[(short) (HEADER_LEN + i - 64)] ^ 0x5C);
                }
                Util.arrayFillNonAtomic(this.hmacKey, (short) 80, (short) 48, (byte) 0x5C);

                apdu.setOutgoingAndSend(ZERO, ZERO);
                break;
            case RSA_SIGN:
                Signature rsa_sig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
                rsa_sig.init(this.keyPair.getPrivate(), Signature.MODE_SIGN);
                short sig_len = rsa_sig.sign(buffer, HEADER_LEN, LEN, buffer, ZERO);
                apdu.setOutgoingAndSend(ZERO, sig_len);
                break;
            case RSA_VERIFY:
                Signature rsa_ver = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
                rsa_ver.init(this.masterKey, Signature.MODE_VERIFY);
                short rsa_data_len = (short) (LEN - RSA_SIGN_LEN - HEADER_LEN);
                boolean rsa_ver_result = rsa_ver.verify(buffer, HEADER_LEN, rsa_data_len, buffer, (short) (LEN - RSA_SIGN_LEN), RSA_SIGN_LEN);
                buffer[0] = (byte) (rsa_ver_result ? 0 : 1);
                apdu.setOutgoingAndSend(ZERO, (short) 1);
                break;
            case RSA_ENC:
                rsaCipher.init(this.masterKey, Cipher.MODE_ENCRYPT);
                short cipher_len = rsaCipher.doFinal(buffer, HEADER_LEN, LEN, buffer, ZERO);
                apdu.setOutgoingAndSend(ZERO, cipher_len);
                break;
            case RSA_DEC:
                rsaCipher.init(this.keyPair.getPrivate(), Cipher.MODE_DECRYPT);
                short text_len = rsaCipher.doFinal(buffer, HEADER_LEN, LEN, buffer, ZERO);
                apdu.setOutgoingAndSend(ZERO, text_len);
                break;
            // case HMAC_SIGN:
            //     Signature hmac = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
            //     hmac.init(this.hmacKey, Signature.MODE_SIGN);
            //     short hmac_len = hmac.sign(buffer, HEADER_LEN, LEN, buffer, ZERO);
            //     apdu.setOutgoingAndSend(ZERO, hmac_len);
            //     break;
            // case HMAC_VERIFY:
            //     Signature ver_hmac = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
            //     ver_hmac.init(this.hmacKey, Signature.MODE_VERIFY);
            //     short hmac_data_len = (short) (LEN - MessageDigest.LENGTH_SHA_256 - HEADER_LEN);
            //     boolean hmac_result = ver_hmac.verify(buffer, HEADER_LEN, hmac_data_len, buffer, (short) (LEN - MessageDigest.LENGTH_SHA_256), MessageDigest.LENGTH_SHA_256);
            //     buffer[0] = (byte) (hmac_result ? 0 : 1);
            //     apdu.setOutgoingAndSend(ZERO, (short) 1);
            //     break;
            case HMAC_SIGN:
                // H(K XOR opad, H(K XOR ipad, text))

                short len = (short) (64 + LEN);

                byte[] tmp1 = new byte[len];
                byte[] tmp2 = new byte[(short) 96];

                MessageDigest m_sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

                Util.arrayCopyNonAtomic(this.hmacKey, ZERO, tmp1, ZERO, (short) 64);
                Util.arrayCopyNonAtomic(buffer, HEADER_LEN, tmp1, (short) 64, LEN);

                // Util.arrayCopyNonAtomic(tmp1, ZERO, buffer, ZERO, len);
                // apdu.setOutgoingAndSend(ZERO, len);

                m_sha256.doFinal(tmp1, ZERO, len, tmp2, (short) 64);

                // Util.arrayCopyNonAtomic(tmp2, (short) 64, buffer, ZERO, MessageDigest.LENGTH_SHA_256);
                // apdu.setOutgoingAndSend(ZERO, MessageDigest.LENGTH_SHA_256);

                Util.arrayCopyNonAtomic(this.hmacKey, (short) 64, tmp2, ZERO, (short) 64);

                // Util.arrayCopyNonAtomic(tmp2, ZERO, buffer, ZERO, (short) 96);
                // apdu.setOutgoingAndSend(ZERO, (short) 96);

                m_sha256.doFinal(tmp2, ZERO, (short) 96, buffer, ZERO);
                apdu.setOutgoingAndSend(ZERO, MessageDigest.LENGTH_SHA_256);

                break;
            case HMAC_VERIFY:

                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

}
