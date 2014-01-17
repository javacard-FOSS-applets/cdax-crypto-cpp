
#include <string>
#include <cstdlib>
#include <iostream>
#include <unistd.h>

#include "card/SmartCard.hpp"
#include "shared/Message.hpp"

using namespace cdax;

void throughputBenchmark()
{
    std::cout << "> starting tests..." << std::endl;

    SmartCard *card = new SmartCard();

    card->setDebug(false);

    if (card == NULL) {
        return;
    }

    if (!card->connect()) {
        return;
    }

    bytestring data;
    int len, repeat = 100;
    byte p1, p2;

    for (int i = 0; i <= 10; i++) {
        len = pow(2, i);
        std::cout << "Sending " << len << " bytes" ;
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            card->transmit(0x05, data);
        }
        card->stopTimer();
    }

    for (int i = 0; i <= 10; i++) {
        len = pow(2, i);
        std::cout << "Receiving " << len << " bytes";
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(0);
            p1 = (len >> 8) & 0xff;
            p2 = len & 0xff;
            card->transmit(0x06, data, p1, p2);
        }
        card->stopTimer();
    }

    for (int i = 0; i <= 10; i++) {
        len = pow(2, i);
        std::cout << "Tranceiving " << len << " bytes";
        card->startTimer();
        for (int j = 0; j < repeat; j++) {
            data.resize(len);
            p1 = (len >> 8) & 0xff;
            p2 = len & 0xff;
            card->transmit(0x06, data, p1, p2);
        }
        card->stopTimer();
    }

}

/**
 * Eceute message unit tests
 * @param  argc ignored
 * @param  argv ignored
 * @return int reponse code
 */
int main(int argc, char* argv[])
{
    throughputBenchmark();

    return 0;
}
