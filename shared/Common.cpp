
#include "Common.hpp"

namespace cdax {

    /**
     * Generate a random string of `length` characters/bytes
     * @param  int length the string length
     * @return string the resulting random string
     */
    std::string randomString(size_t length)
    {
        auto randchar = []() -> char
        {
            const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const size_t max_index = (sizeof(charset) - 1);
            return charset[rand() % max_index];
        };
        std::string str(length, 0);
        std::generate_n(str.begin(), length, randchar);
        return str;
    }


    bool file_exists(const std::string& fileName)
    {
        std::ifstream infile(fileName);
        return infile.good();
    }

}
