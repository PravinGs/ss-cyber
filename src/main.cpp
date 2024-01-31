// #include <iostream>
// #include <fstream>
// #include <string>
// #include <openssl/ec.h>
// #include <openssl/pem.h>
// #include <openssl/evp.h>
// #include <memory>
// #include "../../../../../usr/include/openssl/err.h"

// std::string readFileContent(const std::string &filePath)
// {
//     std::ifstream inputFile(filePath, std::ios::binary);
//     if (!inputFile.is_open())
//     {
//         std::cerr << "Error opening input file." << std::endl;
//         return "";
//     }
//     std::string data((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
//     inputFile.close();
//     return data;
// }

// RSA *readRSACertificate(const bool &isPublic, const std::string &certificatePath, const std::string &password = "")
// {
//     RSA *key = nullptr;
//     FILE *keyFile = fopen(certificatePath.c_str(), "r");
//     if (!keyFile)
//     {
//         std::cerr << "Error opening private key file." << std::endl;
//         return key;
//     }

//     if (isPublic)
//     {
//         (void)password;
//         key = PEM_read_RSA_PUBKEY(keyFile, nullptr, nullptr, nullptr);
//     }
//     else
//     {
//         key = PEM_read_RSAPrivateKey(keyFile, nullptr, nullptr, (void *)password.c_str());
//     }
//     fclose(keyFile);

//     return key;
// }

// EVP_PKEY *readECDSACertificate(const bool &isPublic, const std::string &certificatePath, const std::string &password = "")
// {
//     EVP_PKEY *key = nullptr;
//     FILE *keyFile = fopen(certificatePath.c_str(), "r");
//     if (!keyFile)
//     {
//         std::cerr << "Error opening private key file." << std::endl;
//         return key;
//     }

//     if (isPublic)
//     {
//         (void)password;
//         key = PEM_read_PUBKEY(keyFile, nullptr, nullptr, nullptr);
//     }
//     else
//     {
//         key = PEM_read_PrivateKey(keyFile, nullptr, nullptr, (void *)password.c_str());
//     }
//     fclose(keyFile);

//     return key;
// }

// bool writeSignature(const std::string &signatureFilePath, const std::unique_ptr<unsigned char[]> &signature, const unsigned int &signatureLength)
// {
//     std::ofstream signatureFile(signatureFilePath, std::ios::binary);
//     if (!signatureFile.is_open())
//     {
//         std::cerr << "Error opening signature file." << std::endl;
//         return false;
//     }
//     signatureFile.write(reinterpret_cast<char *>(signature.get()), signatureLength);
//     signatureFile.close();
//     return true;
// }

// bool signWithRSA(const std::string &inputFilePath, const std::string &signatureFilePath, const std::string &privateKeyFilePath, const std::string &privateKeyPassword)
// {

//     std::string fileContent = readFileContent(inputFilePath);

//     if (fileContent.empty())
//         return false;

//     RSA *privateKey = readRSACertificate(false, privateKeyFilePath, privateKeyPassword);

//     if (!privateKey)
//     {
//         ERR_print_errors_fp(stderr);
//         return false;
//     }

//     // Calculate hash of the file
//     unsigned char hash[SHA256_DIGEST_LENGTH];
//     SHA256(reinterpret_cast<const unsigned char *>(fileContent.c_str()), fileContent.length(), hash);

//     // Sign the hash
//     std::unique_ptr<unsigned char[]> signature(new unsigned char[RSA_size(privateKey)]);
//     // unsigned char signature[RSA_size(privateKey)];
//     unsigned int signatureLength;

//     if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature.get(), &signatureLength, privateKey) != 1)
//     {
//         ERR_print_errors_fp(stderr);
//         RSA_free(privateKey);
//         return false;
//     }

//     RSA_free(privateKey);

//     return writeSignature(signatureFilePath, std::move(signature), signatureLength);
// }

// bool verifySignatureWithRSA(const std::string &inputFilePath, const std::string &signatureFilePath, const std::string &publicKeyFilePath)
// {
//     std::string fileContent = readFileContent(inputFilePath);

//     if (fileContent.empty())
//         return false;

//     RSA *publicKey = readRSACertificate(true, publicKeyFilePath);

//     if (!publicKey)
//     {
//         ERR_print_errors_fp(stderr);
//         return false;
//     }

//     std::string signature = readFileContent(signatureFilePath);

//     if (signature.empty()) return false;

//     // Calculate hash of the file
//     unsigned char hash[SHA256_DIGEST_LENGTH];
//     SHA256(reinterpret_cast<const unsigned char *>(fileContent.c_str()), fileContent.length(), hash);

//     int verificationResult = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH,  reinterpret_cast<const unsigned char *>(signature.c_str()), signature.length(), publicKey);

//     RSA_free(publicKey);

//     return (verificationResult == 1);
// }

// int main()
// {
//     // Example usage
//     std::string inputFilePath = "/home/champ/Desktop/ss-cyber/src/sample.txt";
//     std::string signatureFilePath = "/home/champ/Desktop/ss-cyber/src/signature.bin";
//     std::string privateKeyFilePath = "/home/champ/Documents/test/private_key.pem";
//     std::string privateKeyPassword = "Password";
//     std::string publicKeyFilePath = "/home/champ/Documents/test/public_key.pem";

//     // if (signWithRSA(inputFilePath, signatureFilePath, privateKeyFilePath, privateKeyPassword))
//     // {
//     //     std::cout << "Signature created" << '\n';
//     // }
//     if (verifySignatureWithRSA(inputFilePath, signatureFilePath, publicKeyFilePath))
//     {
//         std::cout << "Verification successfull" << '\n';
//     }
//     // if (signDataWithECDSA(inputFilePath, signatureFilePath, privateKeyFilePath, privateKeyPassword))
//     // {
//     //     std::cout << "Data signed successfully" << '\n';
//     //     // std::cout << verifySignatureWithECDSA(inputFilePath, signatureFilePath, publicKeyFilePath) << '\n';
//     // }
//     // std::cout << verifySignatureWithECDSA(inputFilePath, signatureFilePath, publicKeyFilePath) << '\n';

//     return 0;
// }
