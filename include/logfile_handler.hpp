#ifndef LOGFILE_HANDLER_HPP
#define LOGFILE_HANDLER_HPP

#include "common.hpp"

class LogFileHandler
{
public:
    std::uintmax_t megabytesToBytes(const int megaBytes)
    {
        return static_cast<std::uintmax_t>(megaBytes * 1024 * 1024);
    }

    void get_regular_files(const std::string &directory, std::vector<std::string> &files)
    {
        try
        {
            std::string parent = directory;
            for (const auto &entry : std::filesystem::directory_iterator(directory))
            {
                if (std::filesystem::is_regular_file(entry.path()))
                {
                    std::string child = entry.path();
                    files.push_back(child);
                }
            }
        }
        catch (std::exception &e)
        {
            std::string except = e.what();
            std::cout << except << '\n';
            // agent_utils::write_log("os: get_regular_files: " + except, FAILED);
        }
        return;
    }

    int delete_file(const std::string &fileName)
    {
        if (std::filesystem::exists(fileName))
        {
            try
            {
                if (std::filesystem::remove(fileName))
                {
                    return 1;
                }
            }
            catch (const std::exception &e)
            {
                std::string error(e.what());
                // agent_utils::write_log("os: delete_file: " + LOG_ERROR, FAILED);
            }
        }
        return -1;
    }

    int compress_file(const std::string &log_file)
    {
        std::cout << "This thread is going to sleep for 10 secs\n";
        std::this_thread::sleep_for(std::chrono::seconds(10));
        int result = 1;
        std::string line;
        std::string current_file = log_file;
        std::string log_directory = current_file.substr(0, current_file.find_last_of('/'));
        if (log_file == log_file)
        {
            std::vector<std::string> files;
            get_regular_files(log_directory, files);
            current_file += std::to_string(files.size());
        }

        if (current_file.size() == 0)
        {
            // agent_utils::write_log("agent_utils: compress_file: no global log file updated in the code for os", FAILED);
            return -1;
        }

        std::fstream file(log_file, std::ios::in | std::ios::binary);
        if (!file.is_open())
        {
            // agent_utils::write_log("agent_utils: compress_file: no file exist for backup ( " + log_file + " )", FAILED);
            std::cerr << "no file exist for backup " << log_file << '\n';
            return -1;
        }
        gzFile zLog;
        std::string zipFile = current_file + ".gz";
        zLog = gzopen(zipFile.c_str(), "w");
        if (!zLog)
        {
            // agent_utils::write_log("agent_utils: compress_file: " + FCREATION_FAILED + zipFile, FAILED);
            file.close();
            return -1;
        }

        while (std::getline(file, line))
        {
            if (line.size() == 0)
                continue;
            line += '\n';
            if (gzwrite(zLog, line.c_str(), static_cast<unsigned int>(line.size())) != (int)line.size())
            {
                // agent_utils::write_log("agent_utils: compress_file: " + FWRITE_FAILED + zipFile, FAILED);
                result = -1;
                break;
            }
        }
        file.close();
        gzclose(zLog);
        if (result == 1)
        {
            delete_file(current_file);
        }
        else
        {
            // agent_utils::write_log("agent_utils: compress_file: " + FDELETE_FAILED + current_file, FAILED);
            std::cerr << "Compress file failed\n";
        }
        return result;
    }
};

#endif