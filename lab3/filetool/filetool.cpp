#include <fstream>
#include <iostream>
#include <string>

static void read_file(const char* file_name)
{
    std::ifstream in(file_name);
    if (!in.is_open()) {
        std::cout << "file openning failed\n";
        return;
    }
    std::string line;
    while (std::getline(in, line))
        std::cout << line << '\n';
}

static void write_file(const char* file_name, const char* text)
{
    std::ofstream out(file_name);
    if (!out.is_open()) {
        std::cout << "file openning failed\n";
        return;
    }
    out << text << '\n';
}

int main(int argc, char* argv[])
{
    if (argc == 3 && std::string(argv[1]) == "r") {
        read_file(argv[2]);
        return 0;
    }
    if (argc == 4 && std::string(argv[1]) == "w") {
        write_file(argv[2], argv[3]);
        return 0;
    }
    std::cout << "Usage: filetool r <file>\n"
              << "       filetool w <file> <text>\n";
    return 1;
}
