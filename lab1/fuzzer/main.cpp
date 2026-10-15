// Фаззер. МБКС, лаб 2. Функционал:
//—	осуществлять изменение оригинального файла(однобайтовая замена, замена нескольких байт, дозапись в файл);
//—	заменять байты на граничные значения(0x00, 0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF, 0xFFFF / 2, 0xFFFF / 2 + 1, 0xFFFF / 2 - 1 и т.д.);
//—	иметь автоматический режим работы, при котором производится последовательная замена байт в файле;
//—	находить в файле символы, разделяющие поля(“, : = ;”);
//—	расширять значения полей в файле(дописывать в конец, увеличивать длину строк в файле);
//—	осуществлять запуск исследуемой программы;
//—	используя средство динамической бинарной инструментации(DBI) (Intel Pin / DynamoRIO) осуществлять измерение покрытия кода во время фаззинга;
//—	реализовать режим работы фаззера с обратной связью на основе покрытия кода, основанный на сохранении измененных байт в файле с учетом их влияния на покрытие кода программы;
//—	обнаруживать возникновение ошибки в исследуемом приложении;
//—	получать код ошибки и состояние стека и регистров на момент возникновения ошибки;
//—	логировать в файл информацию о произошедших ошибках и соответствующих им входных параметрах(произведенные замены).


#include <iostream>
#include <string>
#include <tchar.h>
#include "fuz.h"

void Welcome();
bool EnterDirs(std::string& source, std::string& result_crash, std::string& result_config);
bool ReadCheckDir(std::string& source);

int main(int argc, char* argv[])
{
	std::string source; //директория, в которой лежат vuln.exe, конфигурационный файл и func.dll
	std::string result_config; //куда будут сохраняться новые конфигурационные файлы
	std::string result_crash; //куда будут сохранятся логи об упавших запусках проги

	Welcome();
	if (false == EnterDirs(source, result_crash, result_config)) return -1;
	Fuz(source, result_crash, result_config);

	return 0;
}

void Welcome()
{
	std::cout << "Welcome to Fuzzer!" << std::endl;
}

// Определяем рабочие директории
bool EnterDirs(std::string& source, std::string& result_crash, std::string& result_config)
{
	//std::cout << "Enter source dir (C:\\Users\\winuser\\Documents\\mbks_labs\\lab1\\source\\): ";
	source = "C:\\Users\\winuser\\Documents\\mbks_labs\\lab1\\source\\";
	if (false == ReadCheckDir(source)) return false;

	//std::cout << "Enter result_crash dir (C:\\Users\\winuser\\Documents\\mbks_labs\\lab1\\result_crash\\): ";
	result_crash = "C:\\Users\\winuser\\Documents\\mbks_labs\\lab1\\result_crash\\";
	if (false == ReadCheckDir(result_crash)) return false;

	//std::cout << "Enter result_config dir (C:\\Users\\winuser\\Documents\\mbks_labs\\lab1\\result_config\\): ";
	result_config = "C:\\Users\\winuser\\Documents\\mbks_labs\\lab1\\result_config\\";
	if (false == ReadCheckDir(result_config)) return false;

	return true;
}

bool ReadCheckDir(std::string& dir)
{
	// Счтываем, что ввел пользователь
	//std::getline(std::cin, dir);
	if (dir.empty())
	{
		std::cerr << "Error: Empty path\n";
		return false;
	}
	// Добавляем разделитель директорий, если его нет в конце пути
	if (dir.back() != '/' && dir.back() != '\\')
	{
		dir += '\\';
	}

	return true;
}