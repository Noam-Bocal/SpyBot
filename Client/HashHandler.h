#pragma once

#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <openssl/evp.h>

class HashHandler
{
public:
    static std::string hash_file(const std::string& filename, const EVP_MD* md = EVP_get_digestbyname("SHA256"));
};