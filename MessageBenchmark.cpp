
#include <ctime>
#include <sys/stat.h>
#include "shared/Message.hpp"

std::vector<double> timer;
const std::string DIRECTORY = "data/";
std::string hostname;

double getTimerMean()
{
    double sum = std::accumulate(timer.begin(), timer.end(), 0.0);
    return sum / timer.size();
}

double getTimerStdev()
{
    double mean = getTimerMean();
    double sq_sum = std::inner_product(timer.begin(), timer.end(), timer.begin(), 0.0);
    return std::sqrt(sq_sum / timer.size() - mean * mean);
}

void openLogFile(std::ofstream& file, const std::string name)
{
    if (file.is_open()) {
        file << std::endl;
        file.close();
    }

    std::cout << ">>>> " << name << std::endl;
    std::string dir = DIRECTORY + hostname;
    mkdir(dir.c_str(), 0777);
    std::string filename = dir + "/" + name + ".dat";
    file.open (filename.c_str());
    file << "bytes\tmilliseconds\terror" << std::endl;
}

int init(int index)
{
    timer.clear();
    return 2 << index;
}

void end(std::ofstream& file, int index)
{
    if (index > 1) {
        int len = 2 << index;
        file << len << "\t" << getTimerMean() << "\t" << getTimerStdev() << std::endl;
        std::cout << "> " << len << " in " << getTimerMean() << " +- " << getTimerStdev() << std::endl;
    }
}

struct timeval start(int len)
{
    struct timeval start_time;
    gettimeofday(&start_time, NULL);
    return start_time;
}

void stop(struct timeval &start)
{
    struct timeval end;
    gettimeofday(&end, NULL);
    double elapsed = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
    timer.push_back(elapsed);
}

int main(int argc, char* argv[])
{
    struct timeval start_time;
    int len;
    cdax::bytestring data;
    std::ofstream file;
    double mean;

    // get hostname
    char tmp[1024];
    tmp[1023] = '\0';
    gethostname(tmp, 1023);
    hostname = tmp;
    std::cout << "> Hostname: " << hostname << std::endl;

    // message stub
    cdax::Message msg("0", "0", "0");

    // create keys
    CryptoPP::AutoSeededRandomPool prng;
    cdax::bytestring key(16);
    prng.GenerateBlock(key.BytePtr(), key.size());
    CryptoPP::RSA::PublicKey clientPub;

    cdax::RSAKeyPair *keypair = new cdax::RSAKeyPair(2048);

    openLogFile(file, "aes_encrypt");

    for (int i = 0; i < 10; i++) {
        len = init(i);
        for (int r = 0; r <= 100; r++) {
            msg.setData(cdax::bytestring(len));
            start_time = start(len);
            msg.aesEncrypt(key);
            stop(start_time);
        }
        end(file, i);
    }

    openLogFile(file, "aes_decrypt");

    for (int i = 0; i < 10; i++) {
        len = init(i);
        for (int r = 0; r <= 100; r++) {
            msg.setData(cdax::bytestring(len));
            msg.aesEncrypt(key);
            start_time = start(len);
            msg.aesDecrypt(key);
            stop(start_time);
        }
        end(file, i);
    }

    openLogFile(file, "hmac");

    for (int i = 0; i < 10; i++) {
        len = init(i);
        for (int r = 0; r <= 100; r++) {
            msg.setData(cdax::bytestring(len));
            start_time = start(len);
            msg.hmac(key);
            stop(start_time);
        }
        end(file, i);
    }

    openLogFile(file, "hmac_verify");

    for (int i = 0; i < 10; i++) {
        len = init(i);
        for (int r = 0; r <= 100; r++) {
            msg.setData(cdax::bytestring(len));
            msg.hmac(key);
            start_time = start(len);
            msg.hmacVerify(key);
            stop(start_time);
        }
        end(file, i);
    }

    openLogFile(file, "rsa_encrypt");

    for (int i = 0; i < 7; i++) {
        len = init(i);
        for (int r = 0; r <= 10; r++) {
            msg.setData(cdax::bytestring(len));
            start_time = start(len);
            msg.encrypt(keypair->getPublic());
            stop(start_time);
        }
        end(file, i);
    }

    openLogFile(file, "rsa_decrypt");

    for (int i = 0; i < 7; i++) {
        len = init(i);
        for (int r = 0; r <= 10; r++) {
            msg.setData(cdax::bytestring(len));
            msg.encrypt(keypair->getPublic());
            start_time = start(len);
            msg.decrypt(keypair->getPrivate());
            stop(start_time);
        }
        end(file, i);
    }

    openLogFile(file, "rsa_sign");

    for (int i = 0; i < 7; i++) {
        len = init(i);
        for (int r = 0; r <= 10; r++) {
            msg.setData(cdax::bytestring(len));
            start_time = start(len);
            msg.sign(keypair->getPrivate());
            stop(start_time);
        }
        end(file, i);
    }

    openLogFile(file, "rsa_verify");

    for (int i = 0; i < 7; i++) {
        len = init(i);
        for (int r = 0; r <= 10; r++) {
            msg.setData(cdax::bytestring(len));
            msg.sign(keypair->getPrivate());
            start_time = start(len);
            msg.verify(keypair->getPublic());
            stop(start_time);
        }
        end(file, i);
    }

    openLogFile(file, "encode");

    for (int i = 0; i < 10; i++) {
        len = init(i);
        for (int r = 0; r <= 10; r++) {
            msg.setData(cdax::bytestring(len));
            start_time = start(len);
            msg.aesEncrypt(key);
            msg.hmac(key);
            stop(start_time);
        }
        end(file, i);
    }

    openLogFile(file, "decode");

    for (int i = 0; i < 10; i++) {
        len = init(i);
        for (int r = 0; r <= 10; r++) {
            msg.setData(cdax::bytestring(len));
            msg.aesEncrypt(key);
            msg.hmac(key);
            start_time = start(len);
            msg.hmacVerify(key);
            msg.aesDecrypt(key);
            stop(start_time);
        }
        end(file, i);
    }
}
