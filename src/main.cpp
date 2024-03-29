#include <logger.hpp>

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
        LOG(logger, log, LOG_DEBUG);
    }
}

void test_iso_with_wrapper_model()
{
    for (int i = 0; i < 110; i++)
    {
        std::string log = "Log line: " + std::to_string(i);
        // logger.log(LogModel(log, LOG_FATAL));
        LOG2(logger, LogModel(log, LOG_AUDIT));
    }
}

int main()
{
    Timer timer;
    test_iso_with_wrapper_model();
    //std::this_thread::sleep_for(std::chrono::milliseconds(2));
    return 0;
}