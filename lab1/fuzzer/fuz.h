#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <filesystem>
#include <Windows.h>
#include <iostream>
#include <iomanip>
#include <tlhelp32.h>
#include <Psapi.h>
#include <DbgHelp.h>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <time.h>
#include <iterator>
#include <vector>
#include <string> 
#include <regex>
#include <random>
#include <functional>
#include "debugger.h"

namespace fs = std::filesystem;

void Fuz(std::string source, std::string result_crash, std::string result_config);
std::string StartDynamoRIO();
int ParseCover(char* file_name);
void Mutation(std::vector<unsigned char>& data);
std::vector<unsigned char> generate_random_data(std::size_t size);
std::vector<unsigned char>FileChoice(std::string directory);
