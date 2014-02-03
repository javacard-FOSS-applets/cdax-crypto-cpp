#pragma once

#include <cstdlib>
#include <iomanip>
#include <string>

#include "bytestring.hpp"
#include "RSAKeyPair.hpp"
#include "TopicKeyPair.hpp"

#define RED      "\033[22;31m"
#define GREEN    "\033[22;32m"
#define YELLOW   "\033[22;33m"
#define BLUE     "\033[22;34m"
#define MAGENTA  "\033[22;35m"
#define CYAN     "\033[22;36m"

namespace cdax {

    std::string randomString(size_t length);

    bool file_exists(const std::string& fileName);
}
