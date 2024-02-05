
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

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#include <zlib.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#endif

#define DEBUG 0
#define INFO 1
#define WARNING 2
#define AUDIT 3
#define ERROR 4
#define CRITICAL 5
#define FATAL 6

#define LOG(logger, message, level) logger.log(message, level, __FILE__, __LINE__, __FUNCTION__)
#define LOG2(logger, logModel) logger.log(logModel, __FILE__, __LINE__, __FUNCTION__)

typedef struct LogModel LogModel;
typedef struct LogBuilder LogBuilder;
enum class TimeFormat
{
    UTC_FORMAT,
    ISO_8601,
    SYSLOG_FORMAT
};

struct LogModel
{
    int lineNo;
    std::string user;
    std::string message;
    int logLevel;
    std::string fileName;
    std::string methodName;

    LogModel() : lineNo(__LINE__), fileName(__FILE__), methodName(__FUNCTION__) {}
    LogModel(const std::string &message, const int logLevel) : LogModel()
    {
        this->message = message;
        this->logLevel = logLevel;
    }
};

struct LogBuilder
{
    long maxFileSize;
    std::string logFilePath;
    int logRange;
    int bufferSize;
    bool rotateByDay;
};

class Logger
{
public:
    static Logger &getInstance()
    {
        static Logger logger;
        return logger;
    }

    static Logger &getInstance(const LogBuilder &logBuilder)
    {
        Logger &logger = Logger::getInstance();
        logger.maxFileSize = logBuilder.maxFileSize;
        logger.logRange = logBuilder.logRange;
        logger.logFilePath = logBuilder.logFilePath;
        logger.bufferSize = logBuilder.bufferSize;
        // logger.rotateByDay = logBuilder.rotateByDay;
        return logger;
    }

    static Logger &getInstance(const std::string &logFilePath)
    {
        Logger &instance = getInstance();
        instance.logFilePath = logFilePath;
        instance.createWriter();
        return instance;
    }

    static Logger &getInstance(const std::string &logFilePath, const TimeFormat &timeFormat)
    {
        Logger &instance = getInstance();
        instance.logFilePath = logFilePath;
        instance.timeFormat = timeFormat;
        instance.createWriter();
        return instance;
    }

    // Logger() : logRange(0), maxFileSize(MAX_LOG_FILE_SIZE), isRunning(false), bufferSize(DEFAULT_BUFFER_SIZE), timeFormat(TimeFormat::UTC_FORMAT)
    // {
    //     init_logger();
    // }

    // Logger(const LogBuilder &logBuilder)
    // {
    //     this->maxFileSize = logBuilder.maxFileSize;
    //     this->logRange = logBuilder.logRange;
    //     this->logFilePath = logBuilder.logFilePath;
    //     this->bufferSize = logBuilder.bufferSize;
    //     this->rotateByDay = logBuilder.rotateByDay;
    //     init_logger();
    // }

    // Logger(const std::string &logFilePath) : Logger()
    // {
    //     this->logFilePath = logFilePath;
    //     createWriter();
    // }

    // Logger(const std::string &logFilePath, const TimeFormat &timeFormat) : Logger(logFilePath)
    // {
    //     this->timeFormat = timeFormat;
    // }

    ~Logger()
    {
        isRunning = false;
        logCondition.notify_one();
        if (asyncTask.valid())
        {
            asyncTask.get();
        }
        if (writter->is_open())
        {
            writter->close();
        }
        delete writter;
    }

    void setLogRange(const int level)
    {
        this->logRange = level;
    }

    void setTimeFormat(const TimeFormat &timeFormat)
    {
        this->timeFormat = timeFormat;
    }

    void setLogFilePath(const std::string &logFilePath)
    {
        this->logFilePath = logFilePath;
        createWriter();
    }

    void setFileSize(const long &fileSize)
    {
        this->maxFileSize = fileSize;
    }

    std::string buildLog(const LogModel &logModel, const char *file, const int line, const char *funcName)
    {
        std::ostringstream stream;
        std::string level = getLogLevelString(logModel.logLevel);
        stream << "[ " << getCurrentTime() << " ]"
               << " " << logModel.user << " "
               << "[ " << file << ": " << line << "-" << funcName << " ] "
               << " [" << level << "] " << logModel.message << '\n';
        return stream.str();
    }

    std::string buildLog(const std::string &message, const int logLevel, const std::string &user, const char *file, const int line, const char *funcName)
    {
        std::ostringstream stream;
        std::string level = getLogLevelString(logLevel);
        stream << "[ " << getCurrentTime() << " ]"
               << " " << user << " "
               << "[ " << file << ": " << line << "-" << funcName << " ] "
               << " [" << level << "] " << message << '\n';

        return stream.str();
    }

    void log(const LogModel &logModel, const char *file = __FILE__, const int line = __LINE__, const char *funcName = __FUNCTION__)
    {
        std::string message = buildLog(logModel, file, line, funcName);
        std::unique_lock<std::mutex> lock(logMutex);
        {
            logQueue.push(message);
            if (logQueue.size() >= bufferSize)
            {
                logCondition.notify_one();
            }
        }
    }

    void log(
        const std::string &message,
        const int level,
        const char *file = "__FILE__",
        const int line = 0,
        const char *funcName = "__FUNCTION__")
    {
        if (logRange < level)
        {
            return;
        }
        std::string logData = buildLog(message, level, this->user, file, line, funcName);
        std::unique_lock<std::mutex> lock(logMutex);
        {

            logQueue.push(logData);

            if (logQueue.size() >= bufferSize)
            {
                logCondition.notify_one();
            }
        }
    }

    void log(
        const std::string &message,
        const int level,
        const std::string &userName = "",
        const char *file = "__FILE__",
        const int line = 0,
        const char *funcName = "__FUNCTION__")
    {
        if (logRange < level)
        {
            return;
        }
        std::string currentUser = (userName.empty()) ? this->user : userName;
        std::string logData = buildLog(message, level, currentUser, file, line, funcName);
        std::unique_lock<std::mutex> lock(logMutex);
        {
            logQueue.push(logData);
            if (logQueue.size() >= bufferSize)
            {
                logCondition.notify_one();
            }
        }
    }

private:
    Logger() : logRange(0), maxFileSize(MAX_LOG_FILE_SIZE), isRunning(false), bufferSize(DEFAULT_BUFFER_SIZE), timeFormat(TimeFormat::UTC_FORMAT)
    {
        init_logger();
    }

    Logger(const Logger &);
    Logger &operator=(const Logger &);

    std::string getLogLevelString(const int &logLevel)
    {
        std::string level;
        switch (logLevel)
        {
        case WARNING:
            level = "WARNING";
            break;
        case INFO:
            level = "INFO";
            break;
        case DEBUG:
            level = "DEBUG";
            break;
        case AUDIT:
            level = "AUDIT";
            break;
        case FATAL:
            level = "FATAL";
            break;
        default:
            level = "TRACE";
            break;
        }
        return level;
    }

    std::string getHostName()
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

    std::string getCurrentTime()
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

    void init_logger()
    {
        user = getHostName();
        writter = new std::fstream;
        asyncTask = std::async(std::launch::async, &Logger::processLogs, this);
    }

    void createWriter()
    {
        if (!writter->is_open())
        {
            writter->open(logFilePath, std::ios::binary | std::ios::app);
            if (writter->is_open())
            {
                isRunning = true;
            }
        }
        else
        {
            isRunning = true;
        }
    }

    /*void processLogs()
    {
        while (isRunning)
        {
            std::unique_lock<std::mutex> lock(logMutex);

            logCondition.wait(lock, [this]
                              { return !logQueue.empty() || !isRunning || (logQueue.size() >= bufferSize); });

            while (!logQueue.empty())
            {
                std::string message = logQueue.front();
                logQueue.pop();

                // Unlock the mutex only while writing to the file
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(10));

                // Write to the file
                writter->write(message.c_str(), message.length());

                // Lock again before checking the next message
                lock.lock();
            }
        }
    }*/

    void processLogs()
    {
        while (isRunning)
        {
            std::ostringstream stream;
            std::unique_lock<std::mutex> lock(logMutex);

            logCondition.wait(lock, [this]
                              { return !logQueue.empty() || !isRunning || (logQueue.size() >= bufferSize); });

            while (!logQueue.empty())
            {
                std::string message = logQueue.front();
                logQueue.pop();
                stream << message;
            }

            lock.unlock();
            writter->write(stream.str().c_str(), stream.str().length());
            backup_log_file();
            lock.lock();
        }
    }

    void backup_log_file()
    {
        std::streampos size;
        if (writter->is_open())
        {
            writter->seekg(0, std::ios::end);
            size = writter->tellg();
        }
        std::cout << "BackUpCall()" << (long)size << '\n';
        if (size >= maxFileSize)
        {
            std::cout << "Logfile size for backup : " << (long)size << '\n';
            compress_file(logFilePath);
            writter->close();
            std::filesystem::remove(logFilePath);
            writter->open(logFilePath, std::ios::app);
        }
    }

    int get_regular_files(const std::string &directory, std::vector<std::string> &files)
    {
        int result = 1;
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
            result = -1;
            std::string except = e.what();
            std::cout << except << '\n';
            // agent_utils::write_log("os: get_regular_files: " + except, FAILED);
        }
        return result;
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
                // agent_utils::write_log("os: delete_file: " + error, FAILED);
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
            line +='\n';
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

private:
    static const int MAX_LOG_FILE_SIZE = 102400;
    static const int DEFAULT_BUFFER_SIZE = 100;
    int logRange;
    long maxFileSize;
    bool isRunning;
    std::size_t bufferSize;
    std::string logFilePath;
    std::fstream *writter = nullptr;
    TimeFormat timeFormat;
    std::string user;
    std::mutex logMutex;
    std::condition_variable logCondition;
    // std::thread logThread;
    std::future<void> asyncTask;
    std::queue<std::string> logQueue;
};

Logger& logger = Logger::getInstance("/home/champ/Desktop/ss-cyber/src/log/sample.txt");

struct Timer
{
    std::chrono::time_point<std::chrono::steady_clock> start, end;
    std::chrono::duration<float> duration;
    Timer()
    {
        start = std::chrono::steady_clock::now();
    }
    ~Timer()
    {
        end = std::chrono::steady_clock::now();
        duration = end - start;
        float ms = duration.count() * 1000.0f;
        std::cout << "Timer took " << ms << "ms\n";
    }
};

void test_utc_timeformat()
{
    logger.setTimeFormat(TimeFormat::SYSLOG_FORMAT);
    for (int i = 0; i < 100; i++)
    {
        std::string log = "Log line: " + std::to_string(i);
        LOG(logger, log, DEBUG);
    }
}

void test_iso_with_wrapper_model()
{
    for (int i = 0; i < 110; i++)
    {
        std::string log = "Log line: " + std::to_string(i);
        LOG2(logger, LogModel(log, AUDIT));
    }
}

int main()
{
    Timer timer;
    test_iso_with_wrapper_model();

    test_utc_timeformat();
    return 0;
}