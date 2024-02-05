#ifndef LOGGER_HPP
#define LOGGER_HPP

#include "logfile_handler.hpp"

#define LOG(logger, message, level) logger.log(message, level, __FILE__, __LINE__, __FUNCTION__)
#define LOG2(logger, logModel) logger.log(logModel, __FILE__, __LINE__, __FUNCTION__)

typedef struct LogModel LogModel;
typedef struct LogBuilder LogBuilder;

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
    int logFilterLevel;
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
        logger.logFilterLevel = logBuilder.logFilterLevel;
        logger.logFilePath = logBuilder.logFilePath;
        logger.bufferSize = logBuilder.bufferSize;
        return logger;
    }

    static Logger &getInstance(const std::string &logFilePath)
    {
        Logger &instance = getInstance();
        instance.logFilePath = logFilePath;
        instance.initFileIOStream();
        return instance;
    }

    static Logger &getInstance(const std::string &logFilePath, const TimeFormat &timeFormat)
    {
        Logger &instance = getInstance();
        instance.logFilePath = logFilePath;
        instance.timeFormat = timeFormat;
        instance.initFileIOStream();
        return instance;
    }

    ~Logger()
    {
        isRunning = false;
        logCondition.notify_one();
        if (asyncTask.valid())
        {
            asyncTask.get();
        }
        if (writer->is_open())
        {
            writer->close();
        }
        delete writer;
    }

    void setlogFilterLevel(const int level)
    {
        this->logFilterLevel = level;
    }

    void setTimeFormat(const TimeFormat &timeFormat)
    {
        this->timeFormat = timeFormat;
    }

    void setLogFilePath(const std::string &logFilePath)
    {
        this->logFilePath = logFilePath;
        initFileIOStream();
    }

    void setFileSize(const long &fileSize)
    {
        this->maxFileSize = fileSize;
    }

    std::string buildLog(const LogModel &logModel, const char *file, const int line, const char *funcName)
    {
        std::ostringstream stream;
        std::string level = getLogLevelString(logModel.logLevel);
        stream << "[ " << OS::getCurrentTime(timeFormat) << " ]"
               << " " << logModel.user << " "
               << "[ " << file << ": " << line << "-" << funcName << " ] "
               << " [" << level << "] " << logModel.message << '\n';
        return stream.str();
    }

    std::string buildLog(const std::string &message, const int logLevel, const std::string &user, const char *file, const int line, const char *funcName)
    {
        std::ostringstream stream;
        std::string level = getLogLevelString(logLevel);
        stream << "[ " << OS::getCurrentTime(timeFormat) << " ]"
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
        if (logFilterLevel < level)
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
        if (logFilterLevel < level)
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
    Logger() : logFilterLevel(0), maxFileSize(MAX_LOG_FILE_SIZE), isRunning(false), bufferSize(DEFAULT_BUFFER_SIZE), timeFormat(TimeFormat::UTC_FORMAT)
    {
        initLogger();
    }

    Logger(const Logger &);
    Logger &operator=(const Logger &);

    std::string getLogLevelString(const int &logLevel)
    {
        std::string level;
        switch (logLevel)
        {
        case LOG_WARNING:
            level = "WARNING";
            break;
        case LOG_INFO:
            level = "INFO";
            break;
        case LOG_DEBUG:
            level = "DEBUG";
            break;
        case LOG_AUDIT:
            level = "AUDIT";
            break;
        case LOG_CRITICAL:
            level = "CRITICAL";
            break;
        case LOG_FATAL:
            level = "FATAL";
            break;
        default:
            level = "TRACE";
            break;
        }
        return level;
    }

    void initLogger()
    {
        user = OS::getHostName();
        writer = new std::fstream;
        asyncTask = std::async(std::launch::async, &Logger::processLogs, this);
    }

    void initFileIOStream()
    {
        if (!writer->is_open())
        {
            writer->open(logFilePath, std::ios::binary | std::ios::app);
            if (writer->is_open())
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
            writer->write(stream.str().c_str(), stream.str().length());
#ifdef __linux__
            backup_log_file();
#endif
            lock.lock();
        }
    }

    void backup_log_file()
    {
        std::streampos size;
        if (writer->is_open())
        {
            writer->seekg(0, std::ios::end);
            size = writer->tellg();
        }
        // std::cout << "BackUpCall()" << (long)size << '\n';
        if (size >= maxFileSize)
        {
            // std::cout << "Logfile size for backup : " << (long)size << '\n';
            logFileHandler.compress_file(logFilePath);
            writer->close();
            std::filesystem::remove(logFilePath);
            writer->open(logFilePath, std::ios::app);
        }
    }

private:
    LogFileHandler logFileHandler;
    static const int MAX_LOG_FILE_SIZE = 102400;
    static const int DEFAULT_BUFFER_SIZE = 100;
    int logFilterLevel;
    long maxFileSize;
    bool isRunning;
    std::size_t bufferSize;
    std::string logFilePath;
    std::fstream *writer = nullptr;
    TimeFormat timeFormat;
    std::string user;
    std::mutex logMutex;
    std::condition_variable logCondition;
    // std::thread logThread;
    std::future<void> asyncTask;
    std::queue<std::string> logQueue;
};

#endif