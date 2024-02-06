#ifndef LOGGER_HPP
#define LOGGER_HPP

#include "logfile_handler.hpp"

/**
 * @brief Macro to simplify logging with file, line number, and function information.
 */
#define LOG(logger, message, level) logger.log(message, level, __FILE__, __LINE__, __FUNCTION__)

/**
 * @brief Macro to simplify logging a pre-defined log model.
 */
#define LOG2(logger, logModel) logger.log(logModel, __FILE__, __LINE__, __FUNCTION__)

/**
 * @brief Structure representing a log model containing message, log level, and user information.
 */
typedef struct LogModel LogModel;

/**
 * @brief Structure representing a builder for configuring a Logger instance.
 */
typedef struct LogBuilder LogBuilder;

/**
 * @brief Represents a log model containing message, log level, and user information.
 */
struct LogModel
{
    int logLevel;        /**< Log level of the message. */
    std::string user;    /**< User associated with the log message. */
    std::string message; /**< Log message content. */

    /**
     * @brief Default constructor for LogModel.
     */
    LogModel() : logLevel(0) {}

    /**
     * @brief Constructor for LogModel with message and log level.
     * @param message The log message content.
     * @param logLevel The log level.
     */
    LogModel(const std::string &message, const int logLevel) : LogModel()
    {
        this->message = message;
        this->logLevel = logLevel;
    }
};

/**
 * @brief Structure representing a builder for configuring a Logger instance.
 */
struct LogBuilder
{
    int maxFileSizeMB;       /**< Maximum log file size in megabytes. */
    int logFilterLevel;      /**< Log filter level. */
    int bufferSize;          /**< Log buffer size. */
    bool rotateByDay;        /**< Flag indicating whether to rotate logs by day. */
    std::string logFilePath; /**< File path for log file. */

    /**
     * @brief Default constructor for LogBuilder.
     */
    LogBuilder() : maxFileSizeMB(1), logFilterLevel(0), bufferSize(100), rotateByDay(0) {}
};

/**
 * @brief Class responsible for logging messages.
 */
class Logger
{
public:
    /**
     * @brief Returns the singleton instance of Logger.
     * @return The singleton instance of Logger.
     */
    static Logger &getInstance();

    /**
     * @brief Returns the singleton instance of Logger with specified configuration.
     * @param logBuilder The LogBuilder containing configuration parameters.
     * @return The singleton instance of Logger with specified configuration.
     */
    static Logger &getInstance(const LogBuilder &logBuilder);

    /**
     * @brief Returns the singleton instance of Logger with specified log file path.
     * @param logFilePath The path to the log file.
     * @return The singleton instance of Logger with specified log file path.
     */
    static Logger &getInstance(const std::string &logFilePath);

    /**
     * @brief Returns the singleton instance of Logger with specified log file path and time format.
     * @param logFilePath The path to the log file.
     * @param timeFormat The time format for log messages.
     * @return The singleton instance of Logger with specified log file path and time format.
     */
    static Logger &getInstance(const std::string &logFilePath, const TimeFormat &timeFormat);

    /**
     * @brief Sets the log filter level.
     * @param level The log filter level to set.
     */
    void setlogFilterLevel(const int level);

    /**
     * @brief Sets the time format for log messages.
     * @param timeFormat The time format to set.
     */
    void setTimeFormat(const TimeFormat &timeFormat);

    /**
     * @brief Sets the log file path.
     * @param logFilePath The path to the log file.
     */
    void setLogFilePath(const std::string &logFilePath);

    /**
     * @brief Sets the maximum log file size in megabytes.
     * @param fileSizeMB The maximum log file size to set.
     */
    void setFileSize(const int &fileSizeMB);

    /**
     * @brief Logs a message using a LogModel.
     * @param logModel The LogModel containing the log message information.
     * @param fileName The name of the file where the log message originated.
     * @param lineNo The line number where the log message originated.
     * @param methodName The name of the method where the log message originated.
     */
    void log(const LogModel &logModel, const char *fileName = "", const int lineNo = 0, const char *methodName = "");

    /**
     * @brief Logs a message with specified log level.
     * @param message The log message content.
     * @param level The log level.
     * @param file The name of the file where the log message originated.
     * @param line The line number where the log message originated.
     * @param funcName The name of the method where the log message originated.
     */
    void log(const std::string &message, const int level, const char *file = "", const int line = 0, const char *funcName = "");

    /**
     * @brief Logs a message with specified log level and user.
     * @param message The log message content.
     * @param level The log level.
     * @param userName The user associated with the log message.
     * @param file The name of the file where the log message originated.
     * @param line The line number where the log message originated.
     * @param funcName The name of the method where the log message originated.
     */
    void log(const std::string &message, const int level, const std::string &userName = "", const char *file = "", const int line = 0, const char *funcName = "");

private:
    /**
     * @brief Default constructor for Logger.
     */
    Logger();

    /**
     * @brief Copy constructor (disabled).
     */
    Logger(const Logger &);

    /**
     * @brief Assignment operator (disabled).
     * @param Logger The Logger instance to copy from.
     * @return The Logger instance.
     */
    Logger &operator=(const Logger &);

    /**
     * @brief Destructor for Logger.
     */
    ~Logger();

    /**
     * @brief Formats a log message with timestamp, user, file, line number, function name, log level, and message content.
     * @param message The log message content.
     * @param logLevel The log level.
     * @param user The user associated with the log message.
     * @param file The name of the file where the log message originated.
     * @param line The line number where the log message originated.
     * @param funcName The name of the method where the log message originated.
     * @return The formatted log message.
     */
    std::string formatLog(const std::string &message, const int logLevel, const std::string &user, const char *file, const int line, const char *funcName);

    /**
     * @brief Converts a log level integer to a corresponding string representation.
     * @param logLevel The log level integer.
     * @return The string representation of the log level.
     */
    std::string convertLogLevelToString(const int &logLevel);

    /**
     * @brief Starts the logger thread.
     */
    void start();

    /**
     * @brief Stops the logger thread.
     */
    void stop();

    /**
     * @brief Initializes the file IO stream for logging.
     */
    void initFileIOStream();

    /**
     * @brief Processes log messages in the log queue and writes them to the log file.
     */
    void processLogs();

    /**
     * @brief Backs up the log file if it exceeds the maximum file size.
     * @param fileName The name of the log file.
     */
    void backupLogFile(const std::string &fileName);

private:
    LogFileHandler logFileHandler;              /**< Log file handler instance. */
    static const int MAX_LOG_FILE_SIZE = 1;     /**< Maximum log file size in megabytes. */
    static const int DEFAULT_BUFFER_SIZE = 100; /**< Default log buffer size. */

    int logFilterLevel;             /**< Log filter level. */
    std::uintmax_t maxFileSize;     /**< Maximum log file size in bytes. */
    bool isRunning;                 /**< Flag indicating whether the logger is running. */
    std::string logFilePath;        /**< Path to the log file. */
    std::fstream *writer = nullptr; /**< File stream for writing logs. */

    // Global values for this Logger instance
    TimeFormat timeFormat; /**< Time format for log messages. */
    std::string user;      /**< User associated with the logger. */

    // Non-blocking logger
    std::mutex logMutex;                  /**< Mutex for thread synchronization. */
    std::condition_variable logCondition; /**< Condition variable for signaling log events. */
    std::thread logThread;                /**< Thread for logging asynchronously. */
    std::queue<std::string> logQueue;     /**< Queue for storing log messages. */
    std::size_t bufferSize;               /**< Size of the log buffer. */
};

#endif
