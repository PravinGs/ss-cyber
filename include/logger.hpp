#ifndef LOGGER_HPP
#define LOGGER_HPP

#include "common.hpp"
#define MAX_LOG_FILE_SIZE 10240
#define DEFAULT_BUFFER_SIZE 10

#define LOG(logger, message, level) logger.log(message, level, __FILE__, __LINE__, __FUNCTION__)
#define LOG2(logger, logModel) logger.log(logModel, __FILE__, __LINE__, __FUNCTION__)


typedef struct LogModel LogModel;

enum class TimeFormat
{
    UTC_FORMAT,
    ISO_8601,
    SYSLOG_FORMAT
};

enum class LogLevel
{
    INFO,
    DEBUG,
    WARNING,
    AUDIT,
    ERROR,
    FATAL
};

struct LogModel
{
    int lineNo;
    std::string user;
    std::string message;
    LogLevel logLevel;
    std::string fileName;
    std::string methodName;

    LogModel() : lineNo(__LINE__), fileName(__FILE__), methodName(__FUNCTION__) {}
    LogModel(const std::string &message, const LogLevel &logLevel) : LogModel()
    {
        this->message = message;
        this->logLevel = logLevel;
    }
};

class Logger
{
public:
    Logger() : maxFileSize(MAX_LOG_FILE_SIZE), isRunning(false), bufferSize(DEFAULT_BUFFER_SIZE), timeFormat(TimeFormat::UTC_FORMAT)
    {
        user = getHostName();
        writter = new std::fstream;
        asyncTask = std::async(std::launch::async, &Logger::processLogs, this);
    }

    Logger(
        const std::string &logFilePath,
        const TimeFormat &timeFormat,
        const long maxFileSize = MAX_LOG_FILE_SIZE,
        const size_t bufferSize = DEFAULT_BUFFER_SIZE) : maxFileSize(maxFileSize), isRunning(true), bufferSize(bufferSize),  logFilePath(logFilePath), timeFormat(timeFormat)
    {
        user = getHostName();
        writter = new std::fstream;
        asyncTask = std::async(std::launch::async, &Logger::processLogs, this);
        init();
    }

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

    void setTimeFormat(const TimeFormat &timeFormat)
    {
        this->timeFormat = timeFormat;
    }

    void setLogFilePath(const std::string &logFilePath)
    {
        this->logFilePath = logFilePath;
        init();
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

    std::string buildLog(const std::string &message, const LogLevel &logLevel, const std::string &user, const char *file, const int line, const char *funcName)
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
        const LogLevel &level,
        const char *file = __FILE__,
        const int line = __LINE__,
        const char *funcName = __FUNCTION__)
    {
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
        const LogLevel &level,
        const std::string &userName = "",
        const char *file = __FILE__,
        const int line = __LINE__,
        const char *funcName = __FUNCTION__)
    {
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
    std::string getLogLevelString(const LogLevel &logLevel)
    {
        std::string level;
        switch (logLevel)
        {
        case LogLevel::WARNING:
            level = "WARNING";
            break;
        case LogLevel::INFO:
            level = "INFO";
            break;
        case LogLevel::DEBUG:
            level = "DEBUG";
            break;
        case LogLevel::AUDIT:
            level = "AUDIT";
            break;
        case LogLevel::FATAL:
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
        char hostname[256];

        if (gethostname(hostname, sizeof(hostname)) == 0)
        {
            hostname[strlen(hostname)] = '\0';
        }
        else
        {
            return "unknown";
        }
        return std::string(hostname);
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
            strftime(current_time, sizeof(current_time), "%a %b %e %H:%M:%S", t);
            break;
        default:
            strftime(current_time, sizeof(current_time), "%Y-%m-%d %H:%M:%S", t);
            break;
        }
        return current_time;
    }

    void init()
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
    void processLogs()
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
    }

private:
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


#endif