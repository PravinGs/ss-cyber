#ifndef CRYPTO_HANDLER_HPP
#define CRYPTO_HANDLER_HPP
#include "common.hpp"

class CryptoHandler
{
private:
    std::string calculateHMAC(const std::string &data, const std::string &key)
    {
        unsigned char result[EVP_MAX_MD_SIZE];
        unsigned int result_len;

        HMAC_CTX *ctx = HMAC_CTX_new();
        HMAC_Init_ex(ctx, key.c_str(), key.length(), EVP_sha256(), NULL);
        HMAC_Update(ctx, reinterpret_cast<const unsigned char *>(data.c_str()), data.length());
        HMAC_Final(ctx, result, &result_len);
        HMAC_CTX_free(ctx);

        // Convert the result to a hexadecimal string
        std::stringstream ss;
        for (unsigned int i = 0; i < result_len; ++i)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)result[i];
        }

        return ss.str();
    }

public:
    void createSignature(const std::string &filePath, const std::string &key)
    {
        std::ifstream file(filePath, std::ios::binary);

        if (!file.is_open())
        {
            std::cerr << "Error opening file: " << filePath << '\n';
            return;
        }

        // Read the contents of the file into a string
        std::string fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        // Calculate HMAC of the file content using the provided key
        std::string signature = calculateHMAC(fileContent, key);

        // Create a signature file with the same name as the original file but with '_signature' appended
        std::string signatureFilePath = filePath + "_signature";
        std::ofstream signatureFile(signatureFilePath);
        if (signatureFile.is_open())
        {
            signatureFile << signature;
            signatureFile.close();
            std::cout << "Signature created successfully: " << signatureFilePath << '\n';
        }
        else
        {
            std::cerr << "Error creating signature file." << '\n';
        }
    }

    bool verifySignature(const std::string &filePath, const std::string &signaturePath, const std::string &key)
    {
        // Read the contents of the file
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open())
        {
            std::cerr << "Error opening file: " << filePath << '\n';
            return false;
        }
        std::string fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        // Read the signature from the signature file
        std::ifstream signatureFile(signaturePath);
        if (!signatureFile.is_open())
        {
            std::cerr << "Error opening signature file: " << signaturePath << '\n';
            return false;
        }
        std::string storedSignature((std::istreambuf_iterator<char>(signatureFile)), std::istreambuf_iterator<char>());
        signatureFile.close();

        // Calculate HMAC of the file content using the provided key
        std::string calculatedSignature = calculateHMAC(fileContent, key);

        // Compare the calculated signature with the stored signature
        return (calculatedSignature == storedSignature);
    }
};

#endif