#include "fuz.h"

#define WORK_DIR "C:\\Users\\winuser\\Documents\\mbks_labs\\lab1\\fuzzer"
#define CONFIG_PATH "C:\\Users\\winuser\\Documents\\mbks_labs\\lab1\\fuzzer\\config_3"
#define TARGET_EXE L"C:\\Users\\winuser\\Documents\\mbks_labs\\lab1\\fuzzer\\vuln3.exe"
#define LOGFILE_MASK "drcov.vuln3.exe.*"

void Fuz(std::string source, std::string result_crash, std::string result_config)
{
	srand((unsigned)time(0));
	std::string cover_file;
	std::vector<unsigned char>changed_buffer;
	time_t start = time(NULL), now = 0, last_saved = now;

	Debugger debugger;
	unsigned int execs = 0, id = 0, crashes = 0, cover = 0, max_cover = 0;
	std::vector<unsigned int>all_covers;
	std::string output_file_name;
	while (1)
	{
		// Выбор конфигурационного файла
		std::vector<unsigned char>changed_buffer = FileChoice(result_config);

		// Мутация файла
		Mutation(changed_buffer);
		std::ofstream out(CONFIG_PATH, std::ios::binary);
		if (out.is_open())
		{
			out.write((const char*)changed_buffer.data(), changed_buffer.size());
		}
		out.close();

		// Запуск исходного exe с измененным конфигом (который должен положить прогу)
		debugger.loadProcess(TARGET_EXE, NULL);
		if (debugger.run(result_crash + "crash" + std::to_string(crashes) + ".log") == FALSE)
		{
			// Сохранение конфигурационного файла, приводящего к падению проги
			output_file_name = result_crash + "crash" + std::to_string(crashes);
			std::ofstream out(output_file_name, std::ios::binary);
			if (out.is_open()) {
				out.write((const char*)changed_buffer.data(), changed_buffer.size());
			}
			out.close();
			crashes++;
		}
		else
		{
			// Расчет покрытия
			cover_file = StartDynamoRIO();
			cover = ParseCover((char*)cover_file.c_str());
			remove(cover_file.c_str());
			
			// Ищем самое большое покрытие
			if (std::find(all_covers.begin(), all_covers.end(), cover) == all_covers.end())
			{
				if (cover > max_cover)
				{
					max_cover = cover;
				}
				all_covers.push_back(cover);

				// Сохраняем конфигурационный файл, который привел к краху программы
				output_file_name = result_config + "crash_config_" + std::to_string(id) + "_cov" + std::to_string(cover);
				std::ofstream out(output_file_name, std::ios::binary);
				if (out.is_open())
				{
					out.write((const char*)changed_buffer.data(), changed_buffer.size());
				}
				out.close();
				id++;
			}

			execs++;
		}
		now = time(NULL);
		if (now - last_saved != 0)
		{
			last_saved = now;
			std::cout << "Time: " << (now - start) << "s\tStarts: " << execs << "\tCrashes: " << crashes << "\tMax coverage: " << max_cover << std::endl << std::endl;
		}
	}
}

// Выбор случайного конфигурационного файла
std::vector<unsigned char>FileChoice(std::string directory)
{
	std::vector<fs::path> files;
	// Просмотр всех файлов в директории
	for (const auto& entry : fs::directory_iterator(directory.c_str()))
	{
		files.push_back(entry.path());
	}

	// Выбор случайного
	int rand_index = rand() % files.size();

	std::ifstream input(files[rand_index], std::ios::binary);
	// Считывание содержимого файла в буфер
	std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(input), {});
	input.close();

	return buffer;
}

void Mutation(std::vector<unsigned char>& data)
{
	int action = rand() % 4;
	int offset = 0, limit_value_offset = 0, number_of_iterations;
	// Граничные значения из условия
	char limit_values[] = { 0x00, 0xFF, 0xFFFF, 0xFF - 1, 0xFFFF - 1, 0xFFFFFFFF - 1 };

	switch (action)
	{
	case 0: // Подстановка граничного значения для переменных программы
	{
		number_of_iterations = rand() % 10;
		for (int i = 0; i < number_of_iterations; i++)
		{
			limit_value_offset = rand() % sizeof(limit_values);
			offset = rand() % 12;
			data[offset] = limit_values[limit_value_offset];
		}
		break;
	}
	case 1: // Создание случайного количества байт и добавление в конец имеющегося буфера
	{
		int number_of_bytes = rand() % 3000;
		std::vector<unsigned char> random_data = generate_random_data(number_of_bytes);
		data.insert(data.end() - 1, random_data.data(), random_data.data() + number_of_bytes);

		break;
	}
	case 2: // Подстановка рандомного значения для переменных программы
	{
		number_of_iterations = rand() % 10;
		for (int i = 0; i < number_of_iterations; i++)
		{
			limit_value_offset = rand() % sizeof(limit_values);
			offset = rand() % 12;
			data[offset] = rand();
		}

		break;
	}
	case 3: // Стирание данных из конца файла
	{
		offset = rand() % data.size();
		int erase_size = rand() % (data.size() - offset);
		data.erase(data.begin() + offset, data.begin() + offset + erase_size);

		break;
	}
	}
}

// Генератор псевдослучайных чисел
std::vector<unsigned char> generate_random_data(std::size_t size)
{
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(1, 255);

	std::vector<unsigned char> data(size);
	for (std::size_t i = 0; i < size; ++i) {
		data[i] = static_cast<unsigned char>(dis(gen));
	}
	return data;
}

// Парсинг полученного от DymamoRIO файла
int ParseCover(char* file_name)
{
	int cover = 0;
	std::string s;
	std::ifstream file(file_name);

	while (getline(file, s))
	{
		if (s.find("module[  0]") != std::string::npos)
		{
			s.erase(0, 24); // Откидываем неинтересующие байты
			cover += atoi(s.c_str());
		}
	}

	file.close();

	return cover;
}

// Запуск утилиты - получаем файл с информацией о покрытии
std::string StartDynamoRIO()
{
	std::regex mask("drcov.vuln3.exe.*");
	std::string result = "";
	system("cd /d C:\\Users\\winuser\\Documents\\mbks_labs\\lab1\\fuzzer && C:\\tools\\DynamoRIO\\bin32\\drrun.exe -root C:\\tools\\DynamoRIO -t drcov -dump_text -logdir C:\\Users\\winuser\\Documents\\mbks_labs\\lab1\\fuzzer -- C:\\Users\\winuser\\Documents\\mbks_labs\\lab1\\fuzzer\\vuln3.exe 1> nul");
	
	for (const auto& entry : fs::directory_iterator(WORK_DIR))
	{
		if (std::regex_match(entry.path().filename().string(), mask)) // Ищем созданный файл
		{
			result = entry.path().string();
			return result; // Возвращаем название файла
		}
	}
	
	result = "";
	return result;
}