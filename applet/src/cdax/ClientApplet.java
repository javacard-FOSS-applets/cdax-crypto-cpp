package cdax;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.framework.JCSystem;

import javacardx.apdu.ExtendedLength;

import javacard.security.KeyPair;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;



public class ClientApplet extends Applet implements ExtendedLength
{
    private static final byte CDAX_CLA = (byte) 0x80;

    private static final byte INIT = (byte) 0x01;

    private static final byte RSA_SIGN = (byte) 0x10;
    private static final byte RSA_VERIFY = (byte) 0x11;
    private static final byte RSA_ENC = (byte) 0x12;
    private static final byte RSA_DEC = (byte) 0x13;

    private static final short HEADER_LEN = 7;

    // rsa key length in bytes
    private static final short RSA_CRT_PARAM_LEN = 128;
    private static final short RSA_MOD_LEN = 256;
    private static final short RSA_EXP_LEN = 3;
    private static final short RSA_SIGN_LEN = 256;

    // client RSA key pair
    private KeyPair keyPair;

    // server public key
    private RSAPublicKey masterKey;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ClientApplet().register(bArray, (short)(bOffset + 1), bArray[bOffset]);
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
            case INIT:
                this.generateKeyPair();
                this.storeMasterKey(buffer);
                RSAPublicKey pub = (RSAPublicKey) this.keyPair.getPublic();
                pub.getModulus(buffer, (short) 0);
                pub.getExponent(buffer, RSA_MOD_LEN);
                apdu.setOutgoingAndSend((short) 0, (short) (RSA_MOD_LEN + RSA_EXP_LEN));
                break;
            case RSA_SIGN:
                Signature signSig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
                signSig.init(this.keyPair.getPrivate(), Signature.MODE_SIGN);
                short sig_len = signSig.sign(buffer, HEADER_LEN, LEN, buffer, (short) (LEN + HEADER_LEN));
                apdu.setOutgoingAndSend((short) (LEN + HEADER_LEN), sig_len);
                break;
            case RSA_VERIFY:
                Signature verSig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
                verSig.init(this.masterKey, Signature.MODE_VERIFY);
                short dataLen = (short) (LEN - RSA_SIGN_LEN - HEADER_LEN);
                boolean result = verSig.verify(buffer, HEADER_LEN, dataLen, buffer, (short) (LEN - RSA_SIGN_LEN), RSA_SIGN_LEN);
                buffer[0] = (byte) (result ? 0 : 1);
                apdu.setOutgoingAndSend((short) 0, (short) 1);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void generateKeyPair()
    {
        this.keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
        this.keyPair.genKeyPair();
    }

    private void storeMasterKey(byte[] buffer)
    {
        this.masterKey = (RSAPublicKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_RSA_PUBLIC,
            KeyBuilder.LENGTH_RSA_2048,
            false
        );
        short offset = HEADER_LEN;
        this.masterKey.setModulus(buffer, offset, RSA_MOD_LEN);
        offset += RSA_MOD_LEN;
        this.masterKey.setExponent(buffer, offset, RSA_EXP_LEN);
    }
}
