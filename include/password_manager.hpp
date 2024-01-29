#ifndef PASSWORD_MANGER_HPP
#define PASSWORD_MANGER_HPP

#include "common.hpp"

class PasswordManager
{
private:
    const int DEFAULT_PASSWORD_LENGTH = 10;

    const std::string UPPERCASE_REGEX_PATTERN = "[A-Z]+";
    const std::string LOWERCASE_REGEX_PETTERN = "[a-z]+";
    const std::string NUMERIC_CASE_REGEX_PATTERN = "[0-9]+";
    const std::string SPECIAL_CHAR_REGEX_PATTERN = "[!@#$%^&*;:]+";

private:
    bool isUpperCaseExist(const std::string &password)
    {
        std::regex upper_case_pattern(UPPERCASE_REGEX_PATTERN);
        bool result = regex_search(password, upper_case_pattern);
        if (!result)
        {
            std::cout << "Password at least contain one upper case letter"
                 << "\n";
            return false;
        }
        return result;
    }

    bool isLowerCaseExist(const std::string &password)
    {
        std::regex lower_case_expression(LOWERCASE_REGEX_PETTERN);
        bool result = regex_search(password, lower_case_expression);
        if (!result)
        {
            std::cout << "Password at least contain one lower case letter" << '\n';
            return false;
        }
        return result;
    }

    bool isNumericCaseExist(const std::string &password)
    {
        std::regex number_expression(NUMERIC_CASE_REGEX_PATTERN);
        bool result = regex_search(password, number_expression);
        if (!result)
        {
            std::cout << "Password at least contain one numeric (0-9) case letter" << '\n';
            return false;
        }

        return result;
    }
    bool isSpecailCharExist(const std::string &password)
    {
        std::regex special_char_expression(SPECIAL_CHAR_REGEX_PATTERN);
        bool result = regex_search(password, special_char_expression);
        if (!result)
        {
            std::cout << "Password at least contain one special character" << '\n';
            return false;
        }
        return result;
    }

    bool isValidSize(const std::string &password, const int length)
    {
        return ((int)password.length() < length) ? false : true;
    }

public:
    bool isValid(const std::string &password, const password_policy &policy)
    {
        if (!isValidSize(password, policy.password_length))
            return false;
        if (policy.upperCase > 0 && !(isUpperCaseExist(password)))
            return false;
        if (policy.lowerCase > 0 && !(isLowerCaseExist(password)))
            return false;
        if (policy.numericCase > 0 && !(isNumericCaseExist(password)))
            return false;
        if (policy.specialCase > 0 && !(isSpecailCharExist(password)))
            return false;
        return true;
    }
    bool isValid(const std::string &password)
    {
        return isValidSize(password, DEFAULT_PASSWORD_LENGTH) &&
               isUpperCaseExist(password) && isLowerCaseExist(password) &&
               isNumericCaseExist(password) && isSpecailCharExist(password);
    }
    bool isValid(const std::string &password, const std::string &policy_file_path);
};

#endif