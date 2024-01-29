#ifndef COMMON_HPP
#define COMMON_HPP
#include <iostream>
#include <string>
#include <regex>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

typedef struct password_policy password_policy;

struct password_policy
{
    int password_length;
    int upperCase;
    int lowerCase;
    int numericCase;
    int specialCase;

    password_policy() : password_length(10), upperCase(1), lowerCase(1), numericCase(1), specialCase(1)
    {
    }
};

#endif