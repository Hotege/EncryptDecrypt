#ifndef _ENCRYPTDECRYPT_H_
#define _ENCRYPTDECRYPT_H_

class EncryptDecrypt
{
public:
	EncryptDecrypt();
	~EncryptDecrypt();

	unsigned char* encrypt(const unsigned char* buffer, const int size, const unsigned char* key, int const keySize);
	unsigned char* encrypt(int& outSize, const char* filename, const unsigned char* key, int const keySize);
	unsigned char* decrypt(const unsigned char* buffer, const int size, const unsigned char* key, const int keySize);
	unsigned char* decrypt(int& outSize, const char* filename, const unsigned char* key, const int keySize);
};

#endif