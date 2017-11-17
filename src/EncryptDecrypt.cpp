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
	m_EnMap = NULL;
	m_DeMap = NULL;
}

EncryptDecrypt::~EncryptDecrypt()
{
	releaseBuffers(m_EnMap, 1 << (sizeof(unsigned short) << 3));
	releaseBuffers(m_DeMap, 1 << (sizeof(unsigned short) << 3));
}

void shuffle(unsigned char* buffer, int size, Random* rd)
{
	for (int i = 0; i < size; i++)
	{
		int id = rd->rand() % (size - i) + i;
		unsigned char t = buffer[i];
		buffer[i] = buffer[id];
		buffer[id] = t;
	}
}

unsigned char* EncryptDecrypt::encrypt(const unsigned char* buffer, const int size, const unsigned char* key, const int keySize)
{
	unsigned char* result = new unsigned char[size];
	AbstractAlgorithm aa;
	Random rd;
	// crc32 for random map
	unsigned int crc32 = aa.getCRC32Value(key, keySize);
	rd.srand(crc32);
	releaseBuffers(m_EnMap, 1 << (sizeof(unsigned short) << 3));
	m_EnMap = new unsigned char*[1 << (sizeof(unsigned short) << 3)];
	for (int i = 0; i < (1 << (sizeof(unsigned short) << 3)); i++)
	{
		m_EnMap[i] = new unsigned char[256];
		for (int j = 0; j < 256; j++)
			m_EnMap[i][j] = j;
		// shuffle by random number
		shuffle(m_EnMap[i], 256, &rd);
	}
	// md5 for sub-key
	unsigned int md5[4];
	aa.getMD5Value(md5, key, keySize);
	unsigned short subKey[8];
	memcpy(subKey, md5, sizeof(unsigned int) * 4);
	int roundID = 0;
	for (int i = 0; i < size; i++)
	{
		result[i] = m_EnMap[subKey[roundID]][buffer[i]];
		roundID = ((roundID + 1) & ((sizeof(unsigned short) << 3) - 1)) == 0 ? 0 : roundID + 1;
	}
	return result;
}

unsigned char* EncryptDecrypt::encrypt(int& outSize, const char* filename, const unsigned char* key, const int keySize)
{
	FILE* file = fopen(filename, "rb");
	fseek(file, 0, SEEK_END);
	int size = ftell(file);
	fseek(file, 0, SEEK_SET);
	unsigned char* buffer = new unsigned char[size];
	fread(buffer, sizeof(unsigned char), size, file);
	fclose(file);
	unsigned char* result = encrypt(buffer, size, key, keySize);
	outSize = size;
	delete[] buffer;
	buffer = NULL;
	return result;
}

unsigned char* EncryptDecrypt::decrypt(const unsigned char* buffer, const int size, const unsigned char* key, int const keySize)
{
	unsigned char* result = new unsigned char[size];
	AbstractAlgorithm aa;
	Random rd;
	// crc32 for random map
	unsigned int crc32 = aa.getCRC32Value(key, keySize);
	rd.srand(crc32);
	releaseBuffers(m_EnMap, 1 << (sizeof(unsigned short) << 3));
	m_EnMap = new unsigned char*[1 << (sizeof(unsigned short) << 3)];
	releaseBuffers(m_DeMap, 1 << (sizeof(unsigned short) << 3));
	m_DeMap = new unsigned char*[1 << (sizeof(unsigned short) << 3)];
	for (int i = 0; i < (1 << (sizeof(unsigned short) << 3)); i++)
	{
		m_EnMap[i] = new unsigned char[256];
		for (int j = 0; j < 256; j++)
			m_EnMap[i][j] = j;
		// shuffle by random number
		shuffle(m_EnMap[i], 256, &rd);
		// calculate decrypt map
		m_DeMap[i] = new unsigned char[256];
		for (int j = 0; j < 256; j++)
			m_DeMap[i][m_EnMap[i][j]] = j;
	}
	// md5 for sub-key
	unsigned int md5[4];
	aa.getMD5Value(md5, key, keySize);
	unsigned short subKey[8];
	memcpy(subKey, md5, sizeof(unsigned int) * 4);
	int roundID = 0;
	for (int i = 0; i < size; i++)
	{
		result[i] = m_DeMap[subKey[roundID]][buffer[i]];
		roundID = ((roundID + 1) & ((sizeof(unsigned short) << 3) - 1)) == 0 ? 0 : roundID + 1;
	}
	return result;
}

unsigned char* EncryptDecrypt::decrypt(int& outSize, const char* filename, const unsigned char* key, const int keySize)
{
	FILE* file = fopen(filename, "rb");
	fseek(file, 0, SEEK_END);
	int size = ftell(file);
	fseek(file, 0, SEEK_SET);
	unsigned char* buffer = new unsigned char[size];
	fread(buffer, sizeof(unsigned char), size, file);
	fclose(file);
	unsigned char* result = decrypt(buffer, size, key, keySize);
	outSize = size;
	delete[] buffer;
	buffer = NULL;
	return result;
}