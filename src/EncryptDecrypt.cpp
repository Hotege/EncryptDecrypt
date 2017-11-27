#include <stdio.h>
#include <memory.h>
#include "EncryptDecrypt.h"
// For more information about AbstractAlgorithm.h, please visit https://github.com/Hotege/AbstractAlgorithm .
#include "AbstractAlgorithm.h"
// For more information about Random.h, please visit https://github.com/Hotege/Random .
#include "Random.h"

void releaseBuffers(unsigned char** buffer, int size)
{
	for (int i = 0; i < size; i++)
		if (buffer != NULL)
		{
			delete[] buffer[i];
			buffer[i] = NULL;
		}
	delete[] buffer;
	buffer = NULL;
}

EncryptDecrypt::EncryptDecrypt()
{

}

EncryptDecrypt::~EncryptDecrypt()
{

}

void shuffle(unsigned char* buffer, int size, Random* rd)
{
	for (int i = 0; i < size; i++)
	{
		int id = rd->random() % (size - i) + i;
		unsigned char t = buffer[i];
		buffer[i] = buffer[id];
		buffer[id] = t;
	}
}

unsigned char* EncryptDecrypt::encrypt(const unsigned char* buffer, const int size, const unsigned char* key, const int keySize, EDSPEED speed, EDCOMPLEXITY complexity)
{
	unsigned char* result = new unsigned char[size];
	AbstractAlgorithm aa;
	Random rd(false);
	// crc32 for random map
	unsigned int crc32 = aa.getCRC32Value(key, keySize);
	rd.init(crc32);

	unsigned int mapSize = 0;
	switch (speed)
	{
		default:
		case EDSP_DEFAULT:
		case EDSP_NORMAL:
		{
			mapSize = 1 << (sizeof(unsigned short) << 3);
			break;
		}
		case EDSP_FAST:
		{
			mapSize = 1 << (sizeof(unsigned char) << 3);
			break;
		}
	}

	unsigned char** pEnMap = NULL;
	pEnMap = new unsigned char*[mapSize];
	for (int i = 0; i < mapSize; i++)
	{
		pEnMap[i] = new unsigned char[256];
		for (int j = 0; j < 256; j++)
			pEnMap[i][j] = j;
		// shuffle by random number
		shuffle(pEnMap[i], 256, &rd);
	}

	unsigned int md5[4], sha1[5], sha256[8];
	aa.getMD5Value(md5, key, keySize);
	aa.getSHA1Value(sha1, key, keySize);
	aa.getSHA256Value(sha256, key, keySize);

	unsigned char* subKey = NULL;
	unsigned int subKeySize = 0;
	int roundID = 0;
	switch (complexity)
	{
		default:
		case EDCO_DEFAULT:
		case EDCO_PRIMARY:
		{
			switch (speed)
			{
				default:
				case EDSP_DEFAULT:
				case EDSP_NORMAL:
				{
					subKey = new unsigned char[4 * sizeof(unsigned int)];
					subKeySize = 4 * sizeof(unsigned int) / sizeof(unsigned short);
					memcpy(subKey, md5, sizeof(unsigned int) * 4);
					break;
				}
				case EDSP_FAST:
				{
					subKey = new unsigned char[4 * sizeof(unsigned int) / sizeof(unsigned char)];
					subKeySize = 4 * sizeof(unsigned int) / sizeof(unsigned char);
					memcpy(subKey, md5, sizeof(unsigned int) * 4);
					break;
				}
			}
			for (int i = 0; i < size; i++)
			{
				int mapID = 0;
				switch (speed)
				{
					default:
					case EDSP_DEFAULT:
					case EDSP_NORMAL:
					{
						mapID = ((unsigned short*)subKey)[roundID];
						break;
					}
					case EDSP_FAST:
					{
						mapID = ((unsigned char*)subKey)[roundID];
						break;
					}
				}
				result[i] = pEnMap[mapID][buffer[i]];
				roundID = ((roundID + 1) & (subKeySize - 1)) == 0 ? 0 : roundID + 1;
			}
			break;
		}
		case EDCO_NORMAL:
		{
			switch (speed)
			{
				default:
				case EDSP_DEFAULT:
				case EDSP_NORMAL:
				{
					subKey = new unsigned char[5 * sizeof(unsigned int)];
					subKeySize = 5 * sizeof(unsigned int) / sizeof(unsigned short);
					memcpy(subKey, sha1, sizeof(unsigned int) * 5);
					break;
				}
				case EDSP_FAST:
				{
					subKey = new unsigned char[5 * sizeof(unsigned int) / sizeof(unsigned char)];
					subKeySize = 5 * sizeof(unsigned int) / sizeof(unsigned char);
					memcpy(subKey, sha1, sizeof(unsigned int) * 5);
					break;
				}
			}
			for (int i = 0; i < size; i++)
			{
				int mapID = 0;
				switch (speed)
				{
					default:
					case EDSP_DEFAULT:
					case EDSP_NORMAL:
					{
						mapID = ((unsigned short*)subKey)[roundID];
						break;
					}
					case EDSP_FAST:
					{
						mapID = ((unsigned char*)subKey)[roundID];
						break;
					}
				}
				result[i] = pEnMap[mapID][buffer[i]];
				roundID = ((roundID + 1) & (subKeySize - 1)) == 0 ? 0 : roundID + 1;
			}
			break;
		}
		case EDCO_ADVANCED:
		{
			switch (speed)
			{
				default:
				case EDSP_DEFAULT:
				case EDSP_NORMAL:
				{
					subKey = new unsigned char[8 * sizeof(unsigned int)];
					subKeySize = 8 * sizeof(unsigned int) / sizeof(unsigned short);
					memcpy(subKey, sha256, sizeof(unsigned int) * 8);
					break;
				}
				case EDSP_FAST:
				{
					subKey = new unsigned char[8 * sizeof(unsigned int) / sizeof(unsigned char)];
					subKeySize = 8 * sizeof(unsigned int) / sizeof(unsigned char);
					memcpy(subKey, sha256, sizeof(unsigned int) * 8);
					break;
				}
			}
			for (int i = 0; i < size; i++)
			{
				int mapID = 0;
				switch (speed)
				{
					default:
					case EDSP_DEFAULT:
					case EDSP_NORMAL:
					{
						mapID = ((unsigned short*)subKey)[roundID];
						break;
					}
					case EDSP_FAST:
					{
						mapID = ((unsigned char*)subKey)[roundID];
						break;
					}
				}
				result[i] = pEnMap[mapID][buffer[i]];
				roundID = ((roundID + 1) & (subKeySize - 1)) == 0 ? 0 : roundID + 1;
			}
			break;
		}
	}
	delete[] subKey; subKey = NULL;

	releaseBuffers(pEnMap, mapSize);
	return result;
}

unsigned char* EncryptDecrypt::encrypt(int& outSize, const char* filename, const unsigned char* key, const int keySize, EDSPEED speed, EDCOMPLEXITY complexity)
{
	FILE* file = fopen(filename, "rb");
	fseek(file, 0, SEEK_END);
	int size = ftell(file);
	fseek(file, 0, SEEK_SET);
	unsigned char* buffer = new unsigned char[size];
	fread(buffer, sizeof(unsigned char), size, file);
	fclose(file);
	unsigned char* result = encrypt(buffer, size, key, keySize, speed, complexity);
	outSize = size;
	delete[] buffer;
	buffer = NULL;
	return result;
}

unsigned char* EncryptDecrypt::decrypt(const unsigned char* buffer, const int size, const unsigned char* key, int const keySize, EDSPEED speed, EDCOMPLEXITY complexity)
{
	unsigned char* result = new unsigned char[size];
	AbstractAlgorithm aa;
	Random rd(false);
	// crc32 for random map
	unsigned int crc32 = aa.getCRC32Value(key, keySize);
	rd.init(crc32);

	unsigned int mapSize = 0;
	switch (speed)
	{
		default:
		case EDSP_DEFAULT:
		case EDSP_NORMAL:
		{
			mapSize = 1 << (sizeof(unsigned short) << 3);
			break;
		}
		case EDSP_FAST:
		{
			mapSize = 1 << (sizeof(unsigned char) << 3);
			break;
		}
	}

	unsigned char** pEnMap = NULL;
	unsigned char** pDeMap = NULL;
	pEnMap = new unsigned char*[mapSize];
	pDeMap = new unsigned char*[mapSize];
	for (int i = 0; i < mapSize; i++)
	{
		pEnMap[i] = new unsigned char[256];
		for (int j = 0; j < 256; j++)
			pEnMap[i][j] = j;
		// shuffle by random number
		shuffle(pEnMap[i], 256, &rd);
		// calculate decrypt map
		pDeMap[i] = new unsigned char[256];
		for (int j = 0; j < 256; j++)
			pDeMap[i][pEnMap[i][j]] = j;
	}

	unsigned int md5[4], sha1[5], sha256[8];
	aa.getMD5Value(md5, key, keySize);
	aa.getSHA1Value(sha1, key, keySize);
	aa.getSHA256Value(sha256, key, keySize);

	unsigned char* subKey = NULL;
	unsigned int subKeySize = 0;
	int roundID = 0;
	switch (complexity)
	{
		default:
		case EDCO_DEFAULT:
		case EDCO_PRIMARY:
		{
			switch (speed)
			{
				default:
				case EDSP_DEFAULT:
				case EDSP_NORMAL:
				{
					subKey = new unsigned char[4 * sizeof(unsigned int)];
					subKeySize = 4 * sizeof(unsigned int) / sizeof(unsigned short);
					memcpy(subKey, md5, sizeof(unsigned int) * 4);
					break;
				}
				case EDSP_FAST:
				{
					subKey = new unsigned char[4 * sizeof(unsigned int) / sizeof(unsigned char)];
					subKeySize = 4 * sizeof(unsigned int) / sizeof(unsigned char);
					memcpy(subKey, md5, sizeof(unsigned int) * 4);
					break;
				}
			}
			for (int i = 0; i < size; i++)
			{
				int mapID = 0;
				switch (speed)
				{
					default:
					case EDSP_DEFAULT:
					case EDSP_NORMAL:
					{
						mapID = ((unsigned short*)subKey)[roundID];
						break;
					}
					case EDSP_FAST:
					{
						mapID = ((unsigned char*)subKey)[roundID];
						break;
					}
				}
				result[i] = pDeMap[mapID][buffer[i]];
				roundID = ((roundID + 1) & (subKeySize - 1)) == 0 ? 0 : roundID + 1;
			}
			break;
		}
		case EDCO_NORMAL:
		{
			switch (speed)
			{
				default:
				case EDSP_DEFAULT:
				case EDSP_NORMAL:
				{
					subKey = new unsigned char[5 * sizeof(unsigned int)];
					subKeySize = 5 * sizeof(unsigned int) / sizeof(unsigned short);
					memcpy(subKey, sha1, sizeof(unsigned int) * 5);
					break;
				}
				case EDSP_FAST:
				{
					subKey = new unsigned char[5 * sizeof(unsigned int) / sizeof(unsigned char)];
					subKeySize = 5 * sizeof(unsigned int) / sizeof(unsigned char);
					memcpy(subKey, sha1, sizeof(unsigned int) * 5);
					break;
				}
			}
			for (int i = 0; i < size; i++)
			{
				int mapID = 0;
				switch (speed)
				{
					default:
					case EDSP_DEFAULT:
					case EDSP_NORMAL:
					{
						mapID = ((unsigned short*)subKey)[roundID];
						break;
					}
					case EDSP_FAST:
					{
						mapID = ((unsigned char*)subKey)[roundID];
						break;
					}
				}
				result[i] = pDeMap[mapID][buffer[i]];
				roundID = ((roundID + 1) & (subKeySize - 1)) == 0 ? 0 : roundID + 1;
			}
			break;
		}
		case EDCO_ADVANCED:
		{
			switch (speed)
			{
				default:
				case EDSP_DEFAULT:
				case EDSP_NORMAL:
				{
					subKey = new unsigned char[8 * sizeof(unsigned int)];
					subKeySize = 8 * sizeof(unsigned int) / sizeof(unsigned short);
					memcpy(subKey, sha256, sizeof(unsigned int) * 8);
					break;
				}
				case EDSP_FAST:
				{
					subKey = new unsigned char[8 * sizeof(unsigned int) / sizeof(unsigned char)];
					subKeySize = 8 * sizeof(unsigned int) / sizeof(unsigned char);
					memcpy(subKey, sha256, sizeof(unsigned int) * 8);
					break;
				}
			}
			for (int i = 0; i < size; i++)
			{
				int mapID = 0;
				switch (speed)
				{
					default:
					case EDSP_DEFAULT:
					case EDSP_NORMAL:
					{
						mapID = ((unsigned short*)subKey)[roundID];
						break;
					}
					case EDSP_FAST:
					{
						mapID = ((unsigned char*)subKey)[roundID];
						break;
					}
				}
				result[i] = pDeMap[mapID][buffer[i]];
				roundID = ((roundID + 1) & (subKeySize - 1)) == 0 ? 0 : roundID + 1;
			}
			break;
		}
	}
	delete[] subKey; subKey = NULL;

	releaseBuffers(pEnMap, mapSize);
	releaseBuffers(pDeMap, mapSize);
	return result;
}

unsigned char* EncryptDecrypt::decrypt(int& outSize, const char* filename, const unsigned char* key, const int keySize, EDSPEED speed, EDCOMPLEXITY complexity)
{
	FILE* file = fopen(filename, "rb");
	fseek(file, 0, SEEK_END);
	int size = ftell(file);
	fseek(file, 0, SEEK_SET);
	unsigned char* buffer = new unsigned char[size];
	fread(buffer, sizeof(unsigned char), size, file);
	fclose(file);
	unsigned char* result = decrypt(buffer, size, key, keySize, speed, complexity);
	outSize = size;
	delete[] buffer;
	buffer = NULL;
	return result;
}