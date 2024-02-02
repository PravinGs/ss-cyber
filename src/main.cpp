#include <logger.hpp>

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
    Logger logger("/home/champ/Desktop/ss-cyber/src/sample.txt");
    for (int i = 0; i < 100; i++)
    {
        std::string log = "Log line: " + std::to_string(i);
        LOG(logger, log, LogLevel::DEBUG);
    }
}

void test_iso_with_wrapper_model()
{
    Logger logger("/home/champ/Desktop/ss-cyber/src/sample.txt", TimeFormat::ISO_8601);
    for (int i = 0; i < 1000; i++)
    {
        std::string log = "Log line: " + std::to_string(i);
        LOG2(logger, LogModel(log, LogLevel::DEBUG));
    }
}

int main()
{
    Timer timer;
    test_utc_timeformat();
    return 0;
}