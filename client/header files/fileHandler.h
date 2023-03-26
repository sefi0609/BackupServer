#pragma once
#include <fstream>
#include <iostream>
#include <string>

using namespace std;

class FileHandler {
private:
	bool readFromInfo(ifstream& myfile, string* data);
	bool wirteToMeFile(string name, uint8_t* clientId, string key);
public:
	long long getFileSize(string filePath);
	bool readBinaryFile(ifstream& myFile, char* buffer, uint32_t bytes);
	bool writeBinaryFile(string filePath, string content);

	friend class ClientLogic;
};