
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
        LPSTR readers_string;
        DWORD readers_string_len;

        rv = SCardListReaders(this->context, NULL, NULL, &readers_string_len);
        readers_string = new char[readers_string_len + 1];
        rv = SCardListReaders(this->context, NULL, readers_string, &readers_string_len);

        if (rv != SCARD_S_SUCCESS) {
            delete readers_string;
            this->last_error = pcsc_stringify_error(rv);
            return false;
        }

        // get friendly name of first reader
        size_t reader_string_len = strlen(readers_string);

        if (reader_string_len == 0) {
            delete readers_string;
            this->last_error = pcsc_stringify_error(rv);
            return false;
        }

        // get first reader string
        this->reader = new char[reader_string_len + 1];
        strcpy(this->reader, readers_string);

        delete readers_string;

        std::cout << "> card reader: " << this->reader << std::endl;

        return true;
    }

    bool SmartCard::waitForCard()
    {
        // get reader state
        SCARD_READERSTATE_A reader_states[1];

        LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &this->context);

        reader_states[0].szReader = this->reader;
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
                    this->reader,
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

                std::cout << "> got card: " << card << std::endl;

                return true;
            }
        }

        // SCardReleaseContext(this->context);

        return true;
    }


    bool SmartCard::transmit(byte* apdu, size_t &apdu_len)
    {
        SCARD_IO_REQUEST pioRecvPci;
        byte* response_buffer = new byte[255];
        DWORD resp_buf_len = 255;

        std::cout << "> send packet: " << hex(apdu, apdu_len) << std::endl;

        LONG rv = SCardTransmit(
            this->card,
            SCARD_PCI_T1,
            apdu,
            apdu_len,
            &pioRecvPci,
            response_buffer,
            &resp_buf_len
        );

        if (rv != SCARD_S_SUCCESS) {
            this->last_error = pcsc_stringify_error(rv);
            return false;
        }

        std::cout << "> receive packet: " << hex(response_buffer, resp_buf_len) << std::endl;

        // strip response code
        resp_buf_len = resp_buf_len - 2;
        // delete apdu;
        apdu = new byte[resp_buf_len];
        apdu_len = resp_buf_len;
        memcpy(apdu, response_buffer, resp_buf_len);
        // delete response_buffer;

        return true;
    }

    bool SmartCard::storePrivateKey(CryptoPP::InvertibleRSAFunction params)
    {
        this->selectApplet();

        size_t header_len = 7;

        size_t p_len = params.GetPrime1().MinEncodedSize();
        size_t q_len = params.GetPrime2().MinEncodedSize();
        size_t pq_len = params.GetMultiplicativeInverseOfPrime2ModPrime1().MinEncodedSize();
        size_t dp1_len = params.GetModPrime1PrivateExponent().MinEncodedSize();
        size_t dq1_len = params.GetModPrime2PrivateExponent().MinEncodedSize();
        size_t data_len = p_len + q_len + pq_len + dp1_len + dq1_len;

        byte* data = new byte[header_len + data_len];

        size_t offset = header_len;
        params.GetPrime1().Encode(data + offset, p_len);
        offset = offset + p_len;
        params.GetPrime2().Encode(data + offset, q_len);
        offset = offset + q_len;
        params.GetMultiplicativeInverseOfPrime2ModPrime1().Encode(data + offset, pq_len);
        offset = offset + pq_len;
        params.GetModPrime1PrivateExponent().Encode(data + offset, dp1_len);
        offset = offset + dp1_len;
        params.GetModPrime2PrivateExponent().Encode(data + offset, dq1_len);
        offset = offset + dq1_len;

        // class byte, instruction byte, length field encoded in 3 bytes
        data[0] = 0x80;
        data[1] = 0x01;
        data[4] = 0x00;
        data[5] = (data_len >> 8) & 0xff;
        data[6] = data_len & 0xff;

        size_t apdu_len = header_len + data_len;
        bool result = this->transmit(data, apdu_len);

        // delete data;

        return result;
    }

    bool SmartCard::signMessage(byte* msg, size_t &msg_len)
    {
        this->selectApplet();

        size_t header_len = 7;

        byte* data = new byte[header_len + msg_len];

        // class byte, instruction byte, length field encoded in 3 bytes
        data[0] = 0x80;
        data[1] = 0x03;
        data[4] = 0x00;
        data[5] = (msg_len >> 8) & 0xff;
        data[6] = msg_len & 0xff;

        memcpy(data + header_len, msg, msg_len);

        size_t apdu_len = header_len + msg_len;
        bool result = this->transmit(data, apdu_len);

        // delete msg;
        msg = new byte[apdu_len];
        msg_len = apdu_len;
        memcpy(msg, data, apdu_len);
        // delete data;

        return result;
    }

    bool SmartCard::selectApplet()
    {
        // select applet apdu
        size_t select_len = 11;
        byte* select = new byte[select_len];
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
        return this->transmit(select, select_len);
    }

};