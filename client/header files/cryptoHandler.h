#pragma once
#include <osrng.h>
#include <rsa.h>
#include <string>
#include <modes.h>
#include <aes.h>
#include "fileHandler.h"
#include <md5.h>
// RSA public key size 128 bytes
#define CIPHER_SIZE  128
#define AES_KEY_LEN  16
// RSA public key stored in x.509 certificate
#define PUBLIC_KEY_LEN 160
using namespace std;
using namespace CryptoPP;

class RSAkeys {
private:
	int saltSize = 64;
	string salt;
	AutoSeededRandomPool rng;
	RSA::PrivateKey privateKey;
	RSA::PublicKey publicKey;
	FileHandler fileHandler;
	string privFile = "priv.key";
	string getPrivateKey();
	bool generateKeys();
	bool writeToFile();
	bool loadFromFile();
	string random_string(size_t length);
public:
	string getPublicKey();
	// SHA1 algorithm
	string decrypt(const char* cipher, unsigned int length);

	friend class ClientLogic;
};

class AESKey {
private:
	unsigned char key[AES_KEY_LEN];
	void loadKey(const unsigned char* _key);
	string encrypt(const char* plain, unsigned int length);

	friend class ClientLogic;
};