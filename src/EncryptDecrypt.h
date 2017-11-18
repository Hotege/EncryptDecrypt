#ifndef _ENCRYPTDECRYPT_H_
#define _ENCRYPTDECRYPT_H_

enum EDSPEED { EDSP_DEFAULT = 0, EDSP_NORMAL, EDSP_FAST };
enum EDCOMPLEXITY { EDCO_DEFAULT = 0, EDCO_PRIMARY, EDCO_NORMAL, EDCO_ADVANCED };

class EncryptDecrypt
{
public:
	EncryptDecrypt();
	~EncryptDecrypt();

	unsigned char* encrypt(const unsigned char* buffer, const int size, const unsigned char* key, int const keySize, EDSPEED speed = EDSP_DEFAULT, EDCOMPLEXITY complexity = EDCO_DEFAULT);
	unsigned char* encrypt(int& outSize, const char* filename, const unsigned char* key, int const keySize, EDSPEED speed = EDSP_DEFAULT, EDCOMPLEXITY complexity = EDCO_DEFAULT);
	unsigned char* decrypt(const unsigned char* buffer, const int size, const unsigned char* key, const int keySize, EDSPEED speed = EDSP_DEFAULT, EDCOMPLEXITY complexity = EDCO_DEFAULT);
	unsigned char* decrypt(int& outSize, const char* filename, const unsigned char* key, const int keySize, EDSPEED speed = EDSP_DEFAULT, EDCOMPLEXITY complexity = EDCO_DEFAULT);
};

#endif