#ifndef PASSWORD_MANGER_HPP
#define PASSWORD_MANGER_HPP

#include "common.hpp"

const int DEFAULT_PASSWORD_LENGTH = 10;

typedef struct PasswordPolicy PasswordPolicy;

struct PasswordPolicy
{
    int passwordLength;
    int upperCase;
    int lowerCase;
    int numericCase;
    int specialCase;

    PasswordPolicy() : passwordLength(DEFAULT_PASSWORD_LENGTH), upperCase(1), lowerCase(1), numericCase(1), specialCase(1)
    {
    }
};

class PasswordManager
{
private:
    const std::string UPPERCASE_REGEX_PATTERN = "[A-Z]+";
    const std::string LOWERCASE_REGEX_PETTERN = "[a-z]+";
    const std::string NUMERIC_CASE_REGEX_PATTERN = "[0-9]+";
    const std::string SPECIAL_CHAR_REGEX_PATTERN = "[!@#$%^&*;:]+";

private:
    bool isUpperCaseExist(const std::string &password, std::string& error)
    {
        std::regex upper_case_pattern(UPPERCASE_REGEX_PATTERN);
        bool result = regex_search(password, upper_case_pattern);
        if (!result)
        {
            error = "Password at least contain one upper case letter";
        }
        return result;
    }

    bool isLowerCaseExist(const std::string &password, std::strin& error)
    {
        std::regex lower_case_expression(LOWERCASE_REGEX_PETTERN);
        bool result = regex_search(password, lower_case_expression);
        if (!result)
        {
            error = "Password at least contain one lower case letter";
        }
        return result;
    }

    bool isNumericCaseExist(const std::string &password, std::string& error)
    {
        std::regex number_expression(NUMERIC_CASE_REGEX_PATTERN);
        bool result = regex_search(password, number_expression);
        if (!result)
        {
            error = "Password at least contain one numeric (0-9) case letter";
        }

        return result;
    }
   
    bool isSpecailCharExist(const std::string &password, std::string& error)
    {
        std::regex special_char_expression(SPECIAL_CHAR_REGEX_PATTERN);
        bool result = regex_search(password, special_char_expression);
        if (!result)
        {
            error = "Password at least contain one special character";
        }
        return result;
    }

    bool isValidSize(const std::string &password, const int length, std::string& error)
    {
        bool result = (int)password.length() < length;
        if (!result)
        {
            error = "Password length is too low";
        }
        return result;
    }

public:
    bool validate(const std::string &password, const PasswordPolicy &policy, std::string& error = "")
    {
        if (!isValidSize(password, policy.passwordLength, error))
            return false;
        if (policy.upperCase > 0 && !(isUpperCaseExist(password, error)))
            return false;
        if (policy.lowerCase > 0 && !(isLowerCaseExist(password, error)))
            return false;
        if (policy.numericCase > 0 && !(isNumericCaseExist(password, error)))
            return false;
        if (policy.specialCase > 0 && !(isSpecailCharExist(password, error)))
            return false;
        return true;
    }
    
    bool validate(const std::string &password, std::string& error = "")
    {
        return isValidSize(password, DEFAULT_PASSWORD_LENGTH, error) &&
               isUpperCaseExist(password, error) && isLowerCaseExist(password, error) &&
               isNumericCaseExist(password, error) && isSpecailCharExist(password, error);
    }
    
    bool validate(const std::string &password, const std::string &policy_file_path);
};

#endif