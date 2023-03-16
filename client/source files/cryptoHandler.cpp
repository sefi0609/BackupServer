#include "cryptoHandler.h"

// genarate pseudo random string - just for salt
// pseudo random is enough for salt,
// salt purpose is to slow down the attacker
string RSAkeys::random_string(size_t length) {
	auto randchar = []() -> char {
		const char charset[] =
			"0123456789"
			"!@#$%^&*"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	string str(length, 0);
	generate_n(str.begin(), length, randchar);
	return str;
}

// generate RSA keys,
// public will be sent to server, private will be saved to priv.key
// return true on success 
bool RSAkeys::generateKeys() {
	try {
		privateKey.GenerateRandomWithKeySize(rng, 1024);
		publicKey = RSA::PublicKey(privateKey);
		// to slow the attacker
		salt = random_string(saltSize);
		return true;
	}
	catch (const exception& e) {
		cout << "Exception at generateKeys(): " << e.what() << endl;
		return false;
	}
}

// get a string representation of the private key - private function 
string RSAkeys::getPrivateKey() {
	string key;
	StringSink ss(key);
	privateKey.Save(ss);
	return key;
}

// get a string representation of the public key
string RSAkeys::getPublicKey() {
	string key;
	StringSink ss(key);
	publicKey.Save(ss);
	return key;
}

// decrypt ciphers encrypted with this public key,
// return plaintext or an empty string if failed to decrypt
string RSAkeys::decrypt(const char* cipher, unsigned int length) {
	string decrypted = "";
	try {
		string decrypted;
		RSAES_OAEP_SHA_Decryptor d(privateKey);
		StringSource ss_cipher(reinterpret_cast<const byte*>(cipher), length, true, new PK_DecryptorFilter(rng, d, new StringSink(decrypted)));
		return decrypted;
	}
	catch (const exception& e) {
		cout << "Exception at decrypt(): " << e.what() << endl;
		return decrypted;
	}
}

// save the private key to priv.key file
bool RSAkeys::writeToFile() {
	string key = getPrivateKey();
	key += salt;
	if (fileHandler.writeBinaryFile(privFile, key))
		return true;
	return false;
}

// get the private key from the file priv.key
bool RSAkeys::loadFromFile() {
	char* tmp = fileHandler.readBinaryFile(privFile);
	// the length of file(key) cannot always be found by strlen - unrecognized characters
	int length = fileHandler.getFileSize(privFile);
	// remove salt
	int keyLength = length - saltSize;
	char* key = new char[keyLength];
	memcpy(key, tmp, keyLength);

	if (key != NULL) {
		StringSource ss(reinterpret_cast<const byte*>(key), length, true);
		privateKey.Load(ss);
		return true;
	}
	else {
		cout << "Can't load private key" << endl;
		return false;
	}
}

// load the AES key (asymmetric key) to the instance of the class 
void AESKey::loadKey(const unsigned char* _key) {
	memcpy(key, _key, AES_KEY_LEN);
}

// encrypt plaintext to send to the server
string AESKey::encrypt(const char* plain, unsigned int length){
	byte iv[AES::BLOCKSIZE] = { 0 };	// as written in maman15

	AES::Encryption aesEncryption(key, AES_KEY_LEN);
	CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	string cipher;
	StreamTransformationFilter stfEncryptor(cbcEncryption, new StringSink(cipher));
	stfEncryptor.Put(reinterpret_cast<const byte*>(plain), length);
	stfEncryptor.MessageEnd();

	return cipher;
}