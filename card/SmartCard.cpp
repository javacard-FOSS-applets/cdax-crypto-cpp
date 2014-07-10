
#include "SmartCard.hpp"

namespace cdax {

    std::string SmartCard::getError()
    {
        return this->last_error;
    }

    bool SmartCard::selectReader()
    {
        // get context
        LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &this->context);

        if (rv != SCARD_S_SUCCESS) {
            this->last_error = pcsc_stringify_error(rv);
            return false;
        }

        // list readers
        DWORD readers_string_len;

        rv = SCardListReaders(this->context, NULL, NULL, &readers_string_len);
        this->reader.resize(readers_string_len + 1, '\0');
        rv = SCardListReaders(this->context, NULL, &this->reader[0], &readers_string_len);

        if (rv != SCARD_S_SUCCESS) {
            this->last_error = pcsc_stringify_error(rv);
            return false;
        }

        // get friendly name of first reader
        if (this->reader.size() == 0) {
            this->last_error = pcsc_stringify_error(rv);
            return false;
        }

        std::cout << "> card reader: " << this->reader << std::endl;

        return true;
    }

    bool SmartCard::waitForCard()
    {
        if (!this->selectReader()) {
            return false;
        }

        // get reader state
        SCARD_READERSTATE_A reader_states[1];

        LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &this->context);

        reader_states[0].szReader = &(this->reader[0]);
        reader_states[0].dwCurrentState = SCARD_STATE_UNAWARE;

        if (rv != SCARD_S_SUCCESS) {
            this->last_error = pcsc_stringify_error(rv);
            return false;
        }

        std::cout << "> waiting for card... " << std::endl;

        while (true) {

            rv = SCardGetStatusChange(this->context, INFINITE, reader_states, 1);

            if (rv != SCARD_S_SUCCESS) {
                break;
            }

            // wait for 0.1 seconds
            usleep(100 * 1000);

            if ((reader_states[0].dwEventState & SCARD_STATE_PRESENT) == SCARD_STATE_PRESENT)
            {

                rv = SCardConnect(
                    this->context,
                    &(this->reader[0]),
                    SCARD_SHARE_SHARED,
                    SCARD_PROTOCOL_T1,
                    &this->card,
                    &this->active_protocol
                );

                if (rv != SCARD_S_SUCCESS)
                {
                    this->last_error = pcsc_stringify_error(rv);
                    return false;
                }

                std::cout << "> got card: " << this->card << std::endl;

                return true;
            }
        }

        // SCardReleaseContext(this->context);

        return true;
    }

    bool SmartCard::connect()
    {
        if (!this->waitForCard()) {
            return false;
        }

        if (!this->selectApplet()) {
            return false;
        }

        return true;
    }

    void SmartCard::release()
    {
        SCardCancel(this->context);
        SCardReleaseContext(this->context);
    }

    void SmartCard::startTimer()
    {
        this->timer.clear();
    }

    double SmartCard::getTimerMean()
    {
        double sum = std::accumulate(this->timer.begin(), this->timer.end(), 0.0);
        return sum / this->timer.size();
    }

    double SmartCard::getTimerStdev()
    {
        double mean = this->getTimerMean();
        double sq_sum = std::inner_product(this->timer.begin(), this->timer.end(), this->timer.begin(), 0.0);
        return std::sqrt(sq_sum / this->timer.size() - mean * mean);
    }

    bool SmartCard::transmit(byte instruction, bytestring &data, byte p1, byte p2)
    {
        SCARD_IO_REQUEST pioRecvPci;
        DWORD resp_buf_len = 2048;
        bytestring response_buffer(resp_buf_len);

        if (instruction != 0x00) {
            bytestring header(7);

            // class byte, instruction byte, length field encoded in 3 bytes
            header[0] = 0x80;
            header[1] = instruction;
            header[2] = p1;
            header[3] = p2;
            header[4] = 0x00;
            header[5] = (data.size() >> 8) & 0xff;
            header[6] = data.size() & 0xff;

            data.Assign(header + data);
        }

        if (true) {
            std::cout << "> send: " << data.hex() << std::endl;
        }

        struct timeval end;
        struct timeval start;
        gettimeofday(&start, NULL);

        LONG rv = SCardTransmit(
            this->card,
            SCARD_PCI_T1,
            data.BytePtr(),
            data.SizeInBytes(),
            &pioRecvPci,
            response_buffer.BytePtr(),
            &resp_buf_len
        );

        gettimeofday(&end, NULL);
        double elapsed = 0.0;
        elapsed = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
        this->timer.push_back(elapsed);


        data.Assign(response_buffer.BytePtr(), resp_buf_len);

        if (true) {
            std::cout << "> recv: " << data.hex() << std::endl;
        }

        if (rv != SCARD_S_SUCCESS) {
            this->last_error = pcsc_stringify_error(rv);
            return false;
        }

        if (data[data.size() - 2] != 0x90 || data[data.size() - 1] != 0x00) {
            return false;
        }

        data.resize(data.size() - 2);

        return true;
    }

    bool SmartCard::storePrivateKey(CryptoPP::RSA::PrivateKey privKey)
    {
        size_t p_len = privKey.GetPrime1().MinEncodedSize();
        size_t q_len = privKey.GetPrime2().MinEncodedSize();
        size_t pq_len = privKey.GetMultiplicativeInverseOfPrime2ModPrime1().MinEncodedSize();
        size_t dp1_len = privKey.GetModPrime1PrivateExponent().MinEncodedSize();
        size_t dq1_len = privKey.GetModPrime2PrivateExponent().MinEncodedSize();
        size_t data_len = p_len + q_len + pq_len + dp1_len + dq1_len;

        bytestring data(data_len);

        size_t offset = 0;
        privKey.GetPrime1().Encode(data.BytePtr() + offset, p_len);
        offset = offset + p_len;
        privKey.GetPrime2().Encode(data.BytePtr() + offset, q_len);
        offset = offset + q_len;
        privKey.GetMultiplicativeInverseOfPrime2ModPrime1().Encode(data.BytePtr() + offset, pq_len);
        offset = offset + pq_len;
        privKey.GetModPrime1PrivateExponent().Encode(data.BytePtr() + offset, dp1_len);
        offset = offset + dp1_len;
        privKey.GetModPrime2PrivateExponent().Encode(data.BytePtr() + offset, dq1_len);
        offset = offset + dq1_len;

        return this->transmit(0x01, data);
    }

    bool SmartCard::selectApplet()
    {
        // select applet apdu
        bytestring select(11);
        select[0] = 0x00;
        select[1] = 0xA4;
        select[2] = 0x04;
        select[3] = 0x00;
        select[4] = 0x06;
        select[5] = 0x00;
        select[6] = 0x00;
        select[7] = 0x00;
        select[8] = 0x00;
        select[9] = 0x00;
        select[10] = 0x42;
        return this->transmit(0x00, select);
    }

    CryptoPP::RSA::PublicKey SmartCard::initialize(CryptoPP::RSA::PublicKey secServerPub)
    {
        size_t mod_len = secServerPub.GetModulus().MinEncodedSize();
        // size_t exp_len = secServerPub.GetPublicExponent().MinEncodedSize();
        size_t exp_len = 3; // always encode in 3 bytes, since the card expects 3 bytes
        size_t data_len = mod_len + exp_len;

        bytestring data;
        CryptoPP::RSA::PublicKey clientPubKey;

        if (!this->transmit(0x01, data)) {
            throw CardException("Did not retrieve client public key");
        }

        if (data.size() < data_len) {
            throw CardException("Response data to small");
        }

        clientPubKey.SetModulus(CryptoPP::Integer(data.BytePtr(), mod_len));
        clientPubKey.SetPublicExponent(CryptoPP::Integer(data.BytePtr() + mod_len, exp_len));

        std::cout << "mod len: " << mod_len << " exp len: " << exp_len << std::endl;

        data.resize(data_len);

        secServerPub.GetModulus().Encode(data.BytePtr(), mod_len);
        secServerPub.GetPublicExponent().Encode(data.BytePtr() + mod_len, exp_len);

        if (!this->transmit(0x02, data)) {
            throw CardException("Could not transmit server public key");
        }

        return clientPubKey;
    }

    bool SmartCard::sign(bytestring &msg)
    {
        return this->transmit(0x10, msg);
    }

    bool SmartCard::encrypt(bytestring &msg)
    {
        return this->transmit(0x12, msg);
    }

    bool SmartCard::decrypt(bytestring &msg)
    {
        return this->transmit(0x13, msg);
    }

    bool SmartCard::verify(bytestring &msg)
    {
        if(!this->transmit(0x11, msg)) {
            return false;
        }

        return (msg[0] == 0);
    }

    bool SmartCard::storeTopicKey(bytestring key, size_t key_index)
    {
        bytestring *tmp_key = new bytestring(key);
        bool result = this->transmit(0x03, *tmp_key, (byte) key_index);
        delete tmp_key;
        return result;
    }

    bool SmartCard::hmac(bytestring &msg, size_t key_index)
    {
        return this->transmit(0x20, msg, (byte) key_index);
    }

    bool SmartCard::hmacVerify(bytestring &msg, size_t key_index)
    {
        if(!this->transmit(0x21, msg, (byte) key_index)) {
            return false;
        }

        return (msg[0] == 0);
    }

    bool SmartCard::aesEncrypt(bytestring &msg, size_t key_index)
    {
        return this->transmit(0x30, msg, (byte) key_index);
    }

    bool SmartCard::aesDecrypt(bytestring &msg, size_t key_index)
    {
        return this->transmit(0x31, msg, (byte) key_index);
    }

    bool SmartCard::handleTopicKeyResponse(bytestring &msg, size_t key_index)
    {
        return this->transmit(0x07, msg, (byte) key_index);
    }

    bool SmartCard::encode(bytestring &msg, size_t key_index)
    {
        return this->transmit(0x08, msg, (byte) key_index);
    }

    bool SmartCard::decode(bytestring &msg, size_t key_index)
    {
        return this->transmit(0x09, msg, (byte) key_index);
    }


};
