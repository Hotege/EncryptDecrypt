#include <stdio.h>
#include <string.h>
#include <time.h>
#include "EncryptDecrypt.h"

int main(int argc, char* argv[])
{
	// int size = strlen(argv[1]);
	// EncryptDecrypt ed;
	// unsigned char* encrypt = ed.encrypt((unsigned char*)argv[1], size, (unsigned char*)argv[2], strlen(argv[2]));
	// for (int i = 0; i < size; i++)
	// 	printf("%d\n", encrypt[i]);
	// unsigned char* decrypt = ed.decrypt(encrypt, size, (unsigned char*)argv[2], strlen(argv[2]));
	// printf("\n");
	// for (int i = 0; i < size; i++)
	// 	printf("%d\n", decrypt[i]);
	// delete[] encrypt;
	// encrypt = NULL;
	// delete[] decrypt;
	// decrypt = NULL;
	char filename[200], encryptname[200], decryptname[200];
	sprintf(filename, "%s", argv[1]);
	sprintf(encryptname, "%s.edx", argv[1]);
	sprintf(decryptname, "de_%s", argv[1]);
	unsigned char key[200];
	memcpy(key, argv[2], strlen(argv[2]));
	int keySize = strlen(argv[2]);
	EncryptDecrypt ed;
	clock_t enT1 = clock();
	int enSize = 0;
	unsigned char* encrypt = ed.encrypt(enSize, filename, key, keySize, EDSP_FAST, EDCO_ADVANCED);
	clock_t enT2 = clock();
	printf("encrypt time: %d ms.\n", (enT2 - enT1) / 1000);
	FILE* out = fopen(encryptname, "wb");
	fwrite(encrypt, sizeof(unsigned char), enSize, out);
	fclose(out);
	clock_t deT1 = clock();
	int deSize = 0;
	unsigned char* decrypt = ed.decrypt(deSize, encryptname, key, keySize, EDSP_FAST, EDCO_ADVANCED);
	clock_t deT2 = clock();
	printf("decrypt time: %d ms.\n", (deT2 - deT1) / 1000);
	FILE* in = fopen(decryptname, "wb");
	fwrite(decrypt, sizeof(unsigned char), deSize, in);
	fclose(in);
	delete[] encrypt;
	encrypt = NULL;
	delete[] decrypt;
	decrypt = NULL;
	return 0;
}