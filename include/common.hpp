#ifndef COMMON_HPP
#define COMMON_HPP
#include <iostream>
#include <string>
#include <cstring>
#include <regex>
#include <future>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <zlib.h>

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#endif

#define LOG_DEBUG 0
#define LOG_INFO 1
#define LOG_WARNING 2
#define LOG_AUDIT 3
#define LOG_ERROR 4
#define LOG_CRITICAL 5
#define LOG_FATAL 6

enum class Hash
{
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512
};

enum class TimeFormat
{
    UTC_FORMAT,
    ISO_8601,
    SYSLOG_FORMAT
};

enum class LogWriter
{
    FILE,
    CONSOLE,
    DATABASE
};

class OS
{
public:
    static std::string getCurrentTime(const TimeFormat& timeFormat)
    {
        char current_time[20];
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        switch (timeFormat)
        {
        case TimeFormat::UTC_FORMAT:
            strftime(current_time, sizeof(current_time), "%Y-%m-%d %H:%M:%S", t);
            break;
        case TimeFormat::ISO_8601:
            strftime(current_time, sizeof(current_time), "%Y-%m-%dT%H:%M:%S", t);
            break;
        case TimeFormat::SYSLOG_FORMAT:
            strftime(current_time, sizeof(current_time), "%a %b %d %H:%M:%S", t);
            break;
        default:
            strftime(current_time, sizeof(current_time), "%Y-%m-%d %H:%M:%S", t);
            break;
        }
        return current_time;
    }

    static std::string getHostName()
    {
#ifdef __linux__
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0)
        {
            hostname[strlen(hostname)] = '\0';
            return std::string(hostname);
        }
#elif _WIN32
        DWORD size = UNLEN + 1; // UNLEN is the maximum length of a user name
        TCHAR buffer[UNLEN + 1];
        if (GetUserName(buffer, &size))
        {
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            return converter.to_bytes(buffer);
        }
#endif
        else
        {
            return "unknown";
        }
    }
};

#endif