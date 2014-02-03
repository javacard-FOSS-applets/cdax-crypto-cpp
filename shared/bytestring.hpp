#pragma once

#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <string>

#include <boost/functional/hash.hpp>
#include <cryptopp/secblock.h>

namespace cdax {

    class bytestring : public CryptoPP::SecByteBlock
    {
    private:

        friend std::ostream &operator<< (std::ostream &out, bytestring &msg);
    public:
        bytestring(size_t size = 0) : CryptoPP::SecByteBlock(size) {};

        bytestring(std::string source);
        bytestring(const char* source);

        const std::string hex() const;
        const std::string str() const;

        const bytestring substr(size_t offset, size_t size) const;

        void clear();
    };

    std::size_t hash_value(bytestring const& b);

}
