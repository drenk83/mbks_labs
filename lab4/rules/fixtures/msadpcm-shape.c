/* Та же форма, что у CVE-2021-3246, с другими именами.
   open_block — слабая проверка: слагаемое chunk сравнивается с произведением,
   множитель nframes так не ограничен.
   open_block_eight — то же с другим множителем, не 7. Правило больше не
   требует литерал 7, поэтому эта функция тоже должна находиться.
   open_block_fixed — как libsndfile 1.1.0: нижняя граница стоит на nframes,
   а chunk слева от сравнения с произведением больше не стоит. Правило молчит. */

#include <stdlib.h>

int open_block(int chunk, int nframes, int channels)
{
	unsigned size;

	if (chunk < 7 * channels) {
		return -1;
	}

	size = sizeof(int) + chunk + 3 * channels * nframes;
	if (!calloc(1, size))
		return -1;
	return 0;
}

int open_block_eight(int chunk, int nframes, int channels)
{
	unsigned size;

	if (chunk < 8 * channels) {
		return -1;
	}

	size = sizeof(int) + chunk + 3 * channels * nframes;
	if (!calloc(1, size))
		return -1;
	return 0;
}

int open_block_fixed(int chunk, int nframes, int channels)
{
	unsigned size;

	if (nframes < 7 * channels)
		return -1;
	if (2 * chunk < nframes * channels)
		return -1;

	size = sizeof(int) + chunk + 3 * channels * nframes;
	if (!calloc(1, size))
		return -1;
	return 0;
}
