#include "HashHandler.h"

std::string HashHandler::hash_file(const std::string& filename, const EVP_MD* md)
{
    // Open the file in binary mode
    std::ifstream file(filename, std::ios::binary);
    if (!file)
        throw std::runtime_error("Failed to open file");

    // Create a new digest context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        throw std::runtime_error("Failed to create digest context");

    // Initialize the digest context with the specified hash function
    if (!EVP_DigestInit_ex(ctx, md, nullptr))
        throw std::runtime_error("Failed to initialize digest context");

    constexpr size_t buffer_size = 4096;  // Size of the buffer used for reading the file in chunks
    char buffer[buffer_size];

    // Read the file in chunks and update the digest context
    while (file) {
        file.read(buffer, buffer_size);
        if (file.gcount() > 0) {
            if (!EVP_DigestUpdate(ctx, buffer, static_cast<size_t>(file.gcount())))
                throw std::runtime_error("Failed to update digest context");
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];  // Buffer to store the final hash
    unsigned int hash_len;

    // Finalize the digest and obtain the hash
    if (!EVP_DigestFinal_ex(ctx, hash, &hash_len))
        throw std::runtime_error("Failed to finalize digest context");

    EVP_MD_CTX_free(ctx);  // Free the digest context

    return std::string(reinterpret_cast<char*>(hash), hash_len);  // Convert the hash to a string and return
}