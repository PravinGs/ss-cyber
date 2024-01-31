#ifndef CRYPTO_HANDLER_HPP
#define CRYPTO_HANDLER_HPP
#include "common.hpp"

class CryptoHandler
{

private:
    std::string readFileContent(const std::string &filePath)
    {
        std::ifstream inputFile(filePath, std::ios::binary);
        if (!inputFile.is_open())
        {
            std::cerr << "Error opening input file." << std::endl;
            return "";
        }
        std::string data((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
        inputFile.close();
        return data;
    }

    EVP_PKEY *readECDSACertificate(const bool &isPublic, const std::string &certificatePath, const std::string &password = "")
    {
        EVP_PKEY *key = nullptr;
        FILE *keyFile = fopen(certificatePath.c_str(), "r");
        if (!keyFile)
        {
            std::cerr << "Error opening private key file." << std::endl;
            return key;
        }

        if (isPublic)
        {
            (void)password;
            key = PEM_read_PUBKEY(keyFile, nullptr, nullptr, nullptr);
        }
        else
        {
            key = PEM_read_PrivateKey(keyFile, nullptr, nullptr, (void *)password.c_str());
        }
        fclose(keyFile);

        return key;
    }

    RSA *readRSACertificate(const bool &isPublic, const std::string &certificatePath, const std::string &password = "")
    {
        RSA *key = nullptr;
        FILE *keyFile = fopen(certificatePath.c_str(), "r");
        if (!keyFile)
        {
            std::cerr << "Error opening private key file." << std::endl;
            return key;
        }

        if (isPublic)
        {
            (void)password;
            key = PEM_read_RSA_PUBKEY(keyFile, nullptr, nullptr, nullptr);
        }
        else
        {
            key = PEM_read_RSAPrivateKey(keyFile, nullptr, nullptr, (void *)password.c_str());
        }
        fclose(keyFile);

        return key;
    }

    bool writeSignature(const std::string &signatureFilePath, const std::unique_ptr<unsigned char[]> &signature, const unsigned int &signatureLength)
    {
        std::ofstream signatureFile(signatureFilePath, std::ios::binary);
        if (!signatureFile.is_open())
        {
            std::cerr << "Error opening signature file." << std::endl;
            return false;
        }
        signatureFile.write(reinterpret_cast<char *>(signature.get()), signatureLength);
        signatureFile.close();
        return true;
    }

private:
    static int passwordCallback(char *buf, int size, int rwflag, void *u)
    {
        (void)rwflag;
        (void)u;
        const char *password = "Password";
        size_t len = strlen(password);

        if (len > static_cast<size_t>(size))
            len = static_cast<size_t>(size);

        memcpy(buf, password, len);
        return static_cast<int>(len);
    }

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

    bool signWithRSA(const char *inputFile, const char *privateKeyFile, const char *signatureFile)
    {
        // Read private key
        FILE *privateKeyFilePtr = fopen(privateKeyFile, "rb");
        if (!privateKeyFilePtr)
        {
            perror("Error opening private key file");
            return false;
        }

        RSA *privateKey = PEM_read_RSAPrivateKey(privateKeyFilePtr, nullptr, passwordCallback, nullptr);
        fclose(privateKeyFilePtr);

        if (!privateKey)
        {
            ERR_print_errors_fp(stderr);
            return false;
        }

        // Read file to sign
        std::ifstream inputFileStream(inputFile, std::ios::binary);
        if (!inputFileStream)
        {
            perror("Error opening input file");
            RSA_free(privateKey);
            return false;
        }

        std::string fileContent((std::istreambuf_iterator<char>(inputFileStream)), std::istreambuf_iterator<char>());
        inputFileStream.close();

        // Calculate hash of the file
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char *>(fileContent.c_str()), fileContent.length(), hash);

        // Sign the hash
        std::unique_ptr<unsigned char[]> signature(new unsigned char[RSA_size(privateKey)]);
        // unsigned char signature[RSA_size(privateKey)];
        unsigned int signatureLength;

        if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature.get(), &signatureLength, privateKey) != 1)
        {
            ERR_print_errors_fp(stderr);
            RSA_free(privateKey);
            return false;
        }

        // Write the signature to a file
        std::ofstream signatureFileStream(signatureFile, std::ios::binary);
        if (!signatureFileStream)
        {
            perror("Error opening signature file");
            RSA_free(privateKey);
            return false;
        }

        signatureFileStream.write(reinterpret_cast<char *>(signature.get()), signatureLength);
        signatureFileStream.close();

        RSA_free(privateKey);

        return true;
    }

    bool verifySignatureWithRSA(const char *inputFile, const char *publicKeyFile, const char *signatureFile)
    {
        // Read public key
        FILE *publicKeyFilePtr = fopen(publicKeyFile, "rb");
        if (!publicKeyFilePtr)
        {
            perror("Error opening public key file");
            return false;
        }

        RSA *publicKey = PEM_read_RSA_PUBKEY(publicKeyFilePtr, nullptr, nullptr, nullptr);
        fclose(publicKeyFilePtr);

        if (!publicKey)
        {
            ERR_print_errors_fp(stderr);
            return false;
        }

        // Read file content
        std::ifstream inputFileStream(inputFile, std::ios::binary);
        if (!inputFileStream)
        {
            perror("Error opening input file");
            RSA_free(publicKey);
            return false;
        }

        std::string fileContent((std::istreambuf_iterator<char>(inputFileStream)), std::istreambuf_iterator<char>());
        inputFileStream.close();

        // Calculate hash of the file
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char *>(fileContent.c_str()), fileContent.length(), hash);

        // Read the signature
        std::ifstream signatureFileStream(signatureFile, std::ios::binary);
        if (!signatureFileStream)
        {
            perror("Error opening signature file");
            RSA_free(publicKey);
            return false;
        }

        signatureFileStream.seekg(0, std::ios::end);
        int signatureLength = signatureFileStream.tellg();
        signatureFileStream.seekg(0, std::ios::beg);

        unsigned char *signature = new unsigned char[signatureLength];
        signatureFileStream.read(reinterpret_cast<char *>(signature), signatureLength);
        signatureFileStream.close();

        // Verify the signature
        int verificationResult = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, signatureLength, publicKey);

        delete[] signature;
        RSA_free(publicKey);

        return (verificationResult == 1);
    }

    bool verifySignatureWithCertificate(const char *inputFile, const char *signatureFile, const char *certificateFile)
    {
        FILE *certificateFilePtr = fopen(certificateFile, "rb");
        if (!certificateFilePtr)
        {
            perror("Error opening certificate file");
            return false;
        }
        X509 *certificate = PEM_read_X509(certificateFilePtr, nullptr, nullptr, nullptr);
        fclose(certificateFilePtr);
        if (!certificate)
        {
            ERR_print_errors_fp(stderr);
            return false;
        }

        // Read file to verify
        std::ifstream inputFileStream(inputFile, std::ios::binary);
        if (!inputFileStream)
        {
            perror("Error opening input file");
            X509_free(certificate);
            return false;
        }

        std::string fileContent((std::istreambuf_iterator<char>(inputFileStream)), std::istreambuf_iterator<char>());
        inputFileStream.close();

        // Calculate hash of the file
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char *>(fileContent.c_str()), fileContent.length(), hash);

        // Read the signature from file
        std::ifstream signatureFileStream(signatureFile, std::ios::binary);
        if (!signatureFileStream)
        {
            perror("Error opening signature file");
            X509_free(certificate);
            return false;
        }

        signatureFileStream.seekg(0, std::ios::end);
        size_t signatureLength = signatureFileStream.tellg();
        signatureFileStream.seekg(0, std::ios::beg);

        unsigned char *signature = new unsigned char[signatureLength];
        signatureFileStream.read(reinterpret_cast<char *>(signature), signatureLength);
        signatureFileStream.close();

        // Verify the X.509 certificate signature
        if (X509_verify(certificate, X509_get_pubkey(certificate)) != 1)
        {
            ERR_print_errors_fp(stderr);
            X509_free(certificate);
            delete[] signature;
            return false;
        }

        // Verify the signature using the calculated hash and the extracted public key
        EVP_PKEY *publicKey = X509_get_pubkey(certificate);
        if (!publicKey)
        {
            ERR_print_errors_fp(stderr);
            X509_free(certificate);
            delete[] signature;
            return false;
        }

        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        if (!md_ctx)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_free(publicKey);
            X509_free(certificate);
            delete[] signature;
            return false;
        }

        if (EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, publicKey) != 1)
        {
            ERR_print_errors_fp(stderr);
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(publicKey);
            X509_free(certificate);
            delete[] signature;
            return false;
        }

        if (EVP_DigestVerify(md_ctx, signature, signatureLength, hash, SHA256_DIGEST_LENGTH) != 1)
        {
            ERR_print_errors_fp(stderr);
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(publicKey);
            X509_free(certificate);
            delete[] signature;
            return false;
        }

        // Clean up
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(publicKey);
        X509_free(certificate);
        delete[] signature;

        return true;
    }

    bool signWithECDSA(const std::string &inputFilePath, const std::string &signatureFilePath, const std::string &privateKeyFilePath, const std::string &privateKeyPassword)
    {
        std::string fileData = readFileContent(inputFilePath);

        if (fileData.empty())
            return false;

        EVP_PKEY *privateKey = readECDSACertificate(false, privateKeyFilePath, privateKeyPassword);

        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_SignInit(mdctx, EVP_sha256());
        EVP_SignUpdate(mdctx, fileData.c_str(), fileData.length());

        std::unique_ptr<unsigned char[]> signature(new unsigned char[EVP_PKEY_size(privateKey)]);
        unsigned int signatureLength;

        if (!EVP_SignFinal(mdctx, signature.get(), &signatureLength, privateKey))
        {
            std::cerr << "Error creating signature." << std::endl;
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(privateKey);
            return false;
        }

        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(privateKey);

        return writeSignature(signatureFilePath, std::move(signature), signatureLength);
    }

    bool verifySignatureWithECDSA(const std::string &inputFilePath, const std::string &signatureFilePath, const std::string &publicKeyFilePath)
    {
        std::string inputData = readFileContent(inputFilePath);

        if (inputData.empty())
            return false;

        std::string signatureData = readFileContent(signatureFilePath);

        if (signatureData.empty())
            return false;

        EVP_PKEY *publicKey = readECDSACertificate(true, publicKeyFilePath);

        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_VerifyInit(mdctx, EVP_sha256());
        EVP_VerifyUpdate(mdctx, inputData.c_str(), inputData.length());

        int result = EVP_VerifyFinal(mdctx, reinterpret_cast<const unsigned char *>(signatureData.c_str()), signatureData.length(), publicKey);

        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(publicKey);

        if (result == 1)
        {
            std::cout << "Signature is valid." << std::endl;
            return true;
        }
        else
        {
            std::cerr << "Signature verification failed." << std::endl;
            return false;
        }
    }

public:
    CryptoHandler() {}

    bool sign(const std::string &inputFile, const std::string &privateKeyFile, const std::string &signatureFile)
    {
        return signWithRSA(inputFile.c_str(), privateKeyFile.c_str(), signatureFile.c_str());
    }

    bool verify(const std::string &inputFile, const std::string &publicKeyFile, const std::string &signatureFile)
    {
        return verifySignatureWithRSA(inputFile.c_str(), publicKeyFile.c_str(), signatureFile.c_str());
    }

    void createHMACSignature(const std::string &filePath, const std::string &outputFile, const std::string &key)
    {
        std::ifstream file(filePath, std::ios::binary);

        if (!file.is_open())
        {
            std::cerr << "Error opening file: " << filePath << '\n';
            return;
        }

        std::string fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        std::string signature = calculateHMAC(fileContent, key);

        std::ofstream signatureFile(outputFile);
        if (signatureFile.is_open())
        {
            signatureFile << signature;
            signatureFile.close();
            std::cout << "Signature created successfully: " << outputFile << '\n';
        }
        else
        {
            std::cerr << "Error creating signature file." << '\n';
        }
    }

    bool verifyHMACSignature(const std::string &filePath, const std::string &signaturePath, const std::string &key)
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