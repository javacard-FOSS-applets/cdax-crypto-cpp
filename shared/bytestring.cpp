
#include "bytestring.hpp"

namespace cdax {

    bytestring::bytestring(std::string source)
    {
        this->Assign((const unsigned char*) source.c_str(), source.size());
    }

    bytestring::bytestring(const char* source)
    {
        this->Assign((const unsigned char*) source, strlen(source) + 1);
    }

    void bytestring::clear()
    {
        this->resize(0);
    }

    const std::string bytestring::hex() const
    {
        std::ostringstream ss;
        ss << '(' << this->size() << " byte) " << std::hex;
        for(std::size_t i = 0; i < this->size(); ++i) {
            if (i != 0) {
                ss << ':';
            }
            ss << (int) (*this)[i];
        }
        return ss.str();
    }

    const std::string bytestring::str()  const
    {
        return std::string(this->begin(), this->end());
    }

    const bytestring bytestring::substr(size_t offset, size_t size)  const
    {
        bytestring result(size);
        result.Assign(this->BytePtr() + offset, size);
        return result;
    }

    /**
     * Overload << operator, to format the content of a message
     * in an output stream. Shows the message data, sender id,
     * topic name and message timestamp
     */
    std::ostream &operator<< (std::ostream &out, const bytestring &data)
    {
        out << std::string(data.m_ptr, data.m_ptr + data.m_size);
        return out;
    }

    std::size_t hash_value(bytestring const& b)
    {
        boost::hash<std::string> hasher;
        return hasher(b.str());
    }

}
