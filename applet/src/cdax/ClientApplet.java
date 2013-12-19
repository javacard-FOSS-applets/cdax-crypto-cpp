package cdax;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.framework.JCSystem;

import javacardx.apdu.ExtendedLength;

import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;



public class ClientApplet extends Applet implements ExtendedLength
{
    private static final byte CDAX_CLA = (byte) 0x80;

    private static final byte STORE_PRIV = (byte) 0x01;
    private static final byte STORE_SERVER_PUB = (byte) 0x02;
    private static final byte SIGN_DATA = (byte) 0x03;

    private static final short HEADER_LEN = 7;
    private static final short PACKET_LEN = 255;

    // rsa key length in bytes
    private static final short RSA_CRT_PARAM_LEN = 64;

    // client private key
    private RSAPrivateCrtKey priv;

    // server public key
    private RSAPublicKey secServerPub;

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
            case STORE_PRIV:
                this.storePrivate(buffer);
                apdu.setOutgoing();
                break;
            case SIGN_DATA:
                Signature sig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
                sig.init(this.priv, Signature.MODE_SIGN);
                short sig_len = sig.sign(buffer, HEADER_LEN, LEN, buffer, (short) (LEN + HEADER_LEN));
                apdu.setOutgoingAndSend((short) (LEN + HEADER_LEN), sig_len);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void storePrivate(byte[] buffer)
    {
        this.priv = (RSAPrivateCrtKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_RSA_CRT_PRIVATE,
            KeyBuilder.LENGTH_RSA_1024,
            false
        );

        short offset = (short) 7;

        this.priv.setP(buffer, offset, RSA_CRT_PARAM_LEN);
        offset += RSA_CRT_PARAM_LEN;
        this.priv.setQ(buffer, offset, RSA_CRT_PARAM_LEN);
        offset += RSA_CRT_PARAM_LEN;
        this.priv.setPQ(buffer, offset, RSA_CRT_PARAM_LEN);
        offset += RSA_CRT_PARAM_LEN;
        this.priv.setDP1(buffer, offset, RSA_CRT_PARAM_LEN);
        offset += RSA_CRT_PARAM_LEN;
        this.priv.setDQ1(buffer, offset, RSA_CRT_PARAM_LEN);
    }
}
