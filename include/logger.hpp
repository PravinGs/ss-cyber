#ifndef LOGGER_HPP
#define LOGGER_HPP

#include "logfile_handler.hpp"

#define LOG(logger, message, level) logger.log(message, level, __FILE__, __LINE__, __FUNCTION__)
#define LOG2(logger, logModel) logger.log(logModel, __FILE__, __LINE__, __FUNCTION__)

typedef struct LogModel LogModel;
typedef struct LogBuilder LogBuilder;

struct LogModel
{
    int logLevel;
    std::string user;
    std::string message;

    LogModel() : logLevel(0) {}

    LogModel(const std::string &message, const int logLevel) : LogModel()
    {
        this->message = message;
        this->logLevel = logLevel;
    }
};

struct LogBuilder
{
    int maxFileSizeMB;
    int logFilterLevel;
    int bufferSize;
    bool rotateByDay;
    std::string logFilePath;
    // LogWriter logWriter;
    LogBuilder() : maxFileSizeMB(1), logFilterLevel(0), bufferSize(100), rotateByDay(0) {}
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
        logger.setFileSize(logBuilder.maxFileSizeMB);
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

    void setFileSize(const int &fileSizeMB)
    {
        this->maxFileSize = logFileHandler.megabytesToBytes(fileSizeMB);
    }

    void log(const LogModel &logModel, const char *fileName = "", const int lineNo = 0, const char *methodName = "")
    {
        std::string message = formatLog(logModel.message, logModel.logLevel, logModel.user, fileName, lineNo, methodName);
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
        const char *file = "",
        const int line = 0,
        const char *funcName = "")
    {
        if (logFilterLevel < level)
        {
            return;
        }
        std::string logData = formatLog(message, level, this->user, file, line, funcName);
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
        const char *file = "",
        const int line = 0,
        const char *funcName = "")
    {
        if (logFilterLevel < level)
        {
            return;
        }
        std::string currentUser = (userName.empty()) ? this->user : userName;
        std::string logData = formatLog(message, level, currentUser, file, line, funcName);
        {
            std::unique_lock<std::mutex> lock(logMutex);
            logQueue.push(logData);
            if (logQueue.size() >= bufferSize)
            {
                logCondition.notify_one();
            }
        }
    }

private:
    Logger() : logFilterLevel(0), maxFileSize(MAX_LOG_FILE_SIZE), isRunning(false), timeFormat(TimeFormat::UTC_FORMAT), bufferSize(DEFAULT_BUFFER_SIZE)
    {
        maxFileSize = logFileHandler.megabytesToBytes(1);
        start();
    }

    Logger(const Logger &);
    Logger &operator=(const Logger &);

    ~Logger()
    {
        stop();
        if (writer->is_open())
        {
            writer->close();
        }
        delete writer;
    }

    std::string formatLog(const std::string &message, const int logLevel, const std::string &user, const char *file, const int line, const char *funcName)
    {
        std::ostringstream stream;
        std::string level = convertLogLevelToString(logLevel);
        stream << "[ " << OS::getCurrentTime(timeFormat) << " ]"
               << " " << user << " "
               << "[ " << file << ": " << line << "-" << funcName << " ] "
               << " [" << level << "] " << message << '\n';

        return stream.str();
    }

    std::string convertLogLevelToString(const int &logLevel)
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

    void start()
    {
        user = OS::getHostName();
        writer = new std::fstream;
        logThread = std::thread(&Logger::processLogs, this);
    }

    void stop()
    {
        logCondition.notify_one(); // Notify the log thread to exit
        isRunning = false;
        if (logThread.joinable())
            logThread.join(); // Wait for the log thread to finish
    }

    void initFileIOStream()
    {
        if(!std::filesystem::exists(logFilePath))
        {
            return ;
        }
        if (!writer->is_open())
        {
            writer->open(logFilePath, std::ios::app);
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
        std::cout << "Process Logs called: with the size of: " << (int)logQueue.size() << '\n';
        while (isRunning)
        {
            std::ostringstream stream;
            {
                std::unique_lock<std::mutex> lock(logMutex);

                logCondition.wait(lock, [this]
                                  { return !logQueue.empty() || !isRunning || (logQueue.size() >= bufferSize); });

                while (!logQueue.empty())
                {
                    std::string message = logQueue.front();
                    logQueue.pop();
                    stream << message;
                }
            } // Realse lock to write file

            {
                std::lock_guard<std::mutex> lock(logMutex);
                writer->write(stream.str().c_str(), stream.str().length());
                backupLogFile(logFilePath);
            }
        }
    }

    void backupLogFile(const std::string &fileName)
    {
        if (!std::filesystem::exists(fileName))
        {
            std::string error = "file not exist " + fileName;
            log(error, LOG_ERROR, __FILE__, __LINE__, __FUNCTION__);
            return;
        }

        std::uintmax_t fileSize = std::filesystem::file_size(fileName);
        if (fileSize >= maxFileSize)
        {
            writer->close();
            logFileHandler.compress_file(fileName);
            writer->open(fileName, std::ios::trunc | std::ios::app);
        }
    }

private:
    LogFileHandler logFileHandler;
    static const int MAX_LOG_FILE_SIZE = 1;
    static const int DEFAULT_BUFFER_SIZE = 100;

    int logFilterLevel;
    std::uintmax_t maxFileSize;
    bool isRunning;
    std::string logFilePath;
    std::fstream *writer = nullptr;

    // Global vlaues to this Logger instance
    TimeFormat timeFormat;
    std::string user;

    // Non blocking logger
    std::mutex logMutex;
    std::condition_variable logCondition;
    // std::future<void> asyncTask;
    std::thread logThread;
    std::queue<std::string> logQueue;
    std::size_t bufferSize;
};

#endif