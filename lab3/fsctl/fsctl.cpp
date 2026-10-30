/* fsctl — консольная программа правил для драйвера FsFilterX.
   Команды:
     fsctl set <путь> <процесс.exe> <чтение 0|1> <запись 0|1>
     fsctl show
     fsctl reload
     fsctl notify on
     fsctl notify off

   set сначала проверяет, что устройство драйвера открывается, затем
   переписывает policy.xml и просит драйвер перечитать файл.
*/
#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <string>
#include <vector>
#include "..\FsFilterX\FsFilterX\ioctl.h"

static const char* kPolicyPathA = "C:\\DriverConfig\\policy.xml";
static const wchar_t* kDevicePath = L"\\\\.\\FsFilterX";

struct Subject {
    std::string name;
    char readFlag;
    char writeFlag;
};

struct FileRule {
    std::string path;
    std::vector<Subject> subjects;
};

static void Usage()
{
    std::wcout << L"fsctl set <путь> <процесс.exe> <чтение 0|1> <запись 0|1>\n"
               << L"fsctl show\n"
               << L"fsctl reload\n"
               << L"fsctl notify on\n"
               << L"fsctl notify off\n";
}

static std::string Trim(const std::string& text)
{
    size_t begin = 0;
    size_t end = text.size();
    while (begin < end && (text[begin] == ' ' || text[begin] == '\t'))
        begin++;
    while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t' || text[end - 1] == '\r'))
        end--;
    return text.substr(begin, end - begin);
}

static bool ReadAttr(const std::string& line, const char* attr, std::string& value)
{
    size_t pos = line.find(attr);
    if (pos == std::string::npos)
        return false;
    pos += std::strlen(attr);
    if (pos >= line.size() || line[pos] != '"')
        return false;
    pos++;
    size_t end = line.find('"', pos);
    if (end == std::string::npos)
        return false;
    value = line.substr(pos, end - pos);
    return !value.empty();
}

static bool LoadPolicy(std::vector<FileRule>& rules, std::wstring& error)
{
    std::ifstream in(kPolicyPathA, std::ios::binary);
    if (!in) {
        rules.clear();
        return true;
    }
    std::string line;
    int fileIndex = -1;
    rules.clear();
    while (std::getline(in, line)) {
        line = Trim(line);
        if (line.compare(0, 6, "<file ") == 0) {
            FileRule rule;
            if (!ReadAttr(line, "path=", rule.path)) {
                error = L"в policy.xml нет path";
                return false;
            }
            rules.push_back(rule);
            fileIndex = (int)rules.size() - 1;
        } else if (line.compare(0, 9, "<subject ") == 0) {
            Subject subject;
            std::string flag;
            if (fileIndex < 0 || !ReadAttr(line, "name=", subject.name)) {
                error = L"в policy.xml испорчен subject";
                return false;
            }
            if (!ReadAttr(line, "read=", flag) || flag.size() != 1 || (flag[0] != '0' && flag[0] != '1')) {
                error = L"в policy.xml испорчен read";
                return false;
            }
            subject.readFlag = flag[0];
            if (!ReadAttr(line, "write=", flag) || flag.size() != 1 || (flag[0] != '0' && flag[0] != '1')) {
                error = L"в policy.xml испорчен write";
                return false;
            }
            subject.writeFlag = flag[0];
            rules[fileIndex].subjects.push_back(subject);
        }
    }
    return true;
}

static bool SavePolicy(const std::vector<FileRule>& rules, std::wstring& error)
{
    std::ofstream out(kPolicyPathA, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = L"не удалось записать policy.xml";
        return false;
    }
    out << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<policy>\r\n";
    for (size_t i = 0; i < rules.size(); i++) {
        out << "  <file path=\"" << rules[i].path << "\">\r\n";
        for (size_t j = 0; j < rules[i].subjects.size(); j++) {
            const Subject& subject = rules[i].subjects[j];
            out << "    <subject name=\"" << subject.name
                << "\" read=\"" << subject.readFlag
                << "\" write=\"" << subject.writeFlag << "\"/>\r\n";
        }
        out << "  </file>\r\n";
    }
    out << "</policy>\r\n";
    return true;
}

static std::string ReadFileBytes()
{
    std::ifstream in(kPolicyPathA, std::ios::binary);
    std::ostringstream data;
    data << in.rdbuf();
    return data.str();
}

static bool WriteFileBytes(const std::string& bytes)
{
    std::ofstream out(kPolicyPathA, std::ios::binary | std::ios::trunc);
    if (!out)
        return false;
    out << bytes;
    return (bool)out;
}

static HANDLE OpenDevice()
{
    return CreateFileW(kDevicePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
}

static bool SendIoctl(DWORD code)
{
    HANDLE device = OpenDevice();
    DWORD returned = 0;
    BOOL ok;
    if (device == INVALID_HANDLE_VALUE) {
        std::wcout << L"устройство не открылось\n";
        return false;
    }
    ok = DeviceIoControl(device, code, NULL, 0, NULL, 0, &returned, NULL);
    CloseHandle(device);
    if (!ok)
        std::wcout << L"IOCTL не выполнен, код " << GetLastError() << L"\n";
    return ok == TRUE;
}

static bool FlagOk(const char* text)
{
    return text != NULL && text[0] != 0 && text[1] == 0 && (text[0] == '0' || text[0] == '1');
}

static int CommandSet(int argc, char** argv)
{
    std::vector<FileRule> rules;
    std::wstring error;
    std::string previous;
    HANDLE device;
    bool foundFile = false;
    size_t i;

    if (argc != 6 || !FlagOk(argv[4]) || !FlagOk(argv[5])) {
        Usage();
        return 1;
    }

    device = OpenDevice();
    if (device == INVALID_HANDLE_VALUE) {
        std::wcout << L"устройство не открылось\n";
        return 1;
    }
    CloseHandle(device);

    if (!LoadPolicy(rules, error)) {
        std::wcout << error << L"\n";
        return 1;
    }
    previous = ReadFileBytes();

    for (i = 0; i < rules.size(); i++) {
        size_t j;
        if (rules[i].path != argv[2])
            continue;
        foundFile = true;
        for (j = 0; j < rules[i].subjects.size(); j++) {
            if (rules[i].subjects[j].name == argv[3]) {
                rules[i].subjects[j].readFlag = argv[4][0];
                rules[i].subjects[j].writeFlag = argv[5][0];
                break;
            }
        }
        if (j == rules[i].subjects.size()) {
            Subject subject;
            subject.name = argv[3];
            subject.readFlag = argv[4][0];
            subject.writeFlag = argv[5][0];
            rules[i].subjects.push_back(subject);
        }
        break;
    }
    if (!foundFile) {
        FileRule rule;
        Subject subject;
        rule.path = argv[2];
        subject.name = argv[3];
        subject.readFlag = argv[4][0];
        subject.writeFlag = argv[5][0];
        rule.subjects.push_back(subject);
        rules.push_back(rule);
    }

    if (!SavePolicy(rules, error)) {
        std::wcout << error << L"\n";
        return 1;
    }
    if (!SendIoctl(IOCTL_FSFILTERX_RELOAD)) {
        if (!previous.empty())
            WriteFileBytes(previous);
        else
            DeleteFileA(kPolicyPathA);
        SendIoctl(IOCTL_FSFILTERX_RELOAD);
        std::wcout << L"правила на диске возвращены\n";
        return 1;
    }
    std::wcout << L"правила обновлены\n";
    return 0;
}

static int CommandShow()
{
    std::ifstream in(kPolicyPathA, std::ios::binary);
    if (!in) {
        std::wcout << L"policy.xml не открылся\n";
        return 1;
    }
    std::cout << in.rdbuf();
    return 0;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        Usage();
        return 1;
    }
    std::string command = argv[1];
    if (command == "set")
        return CommandSet(argc, argv);
    if (command == "show")
        return CommandShow();
    if (command == "reload")
        return SendIoctl(IOCTL_FSFILTERX_RELOAD) ? 0 : 1;
    if (command == "notify" && argc == 3 && std::string(argv[2]) == "on")
        return SendIoctl(IOCTL_FSFILTERX_NOTIFY_ON) ? 0 : 1;
    if (command == "notify" && argc == 3 && std::string(argv[2]) == "off")
        return SendIoctl(IOCTL_FSFILTERX_NOTIFY_OFF) ? 0 : 1;
    Usage();
    return 1;
}
