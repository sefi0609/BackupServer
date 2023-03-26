#include "fileHandler.h"

// read from files transfer.info and me.info,
// those files have the same structure, return true on sucsses
bool FileHandler::readFromInfo(ifstream& myfile, string* data) {
	string temp;
	if (myfile.is_open()) {
		for (int i = 0; i < 3; i++) {
			getline(myfile, temp);
			data[i] = temp;
		}
		return true;
	}
	else {
		cout << "me.info file doesn't exist" << endl;;
		return false;
	}
}

// save the client name, id and AES key to me.info file,
// return true on sucsses
bool FileHandler::wirteToMeFile(string name, uint8_t* clientId, string key) {
	try {
		ofstream file("me.info", ifstream::binary);

		file << name << endl;
		file << clientId << endl;
		// AES key
		file << key;
		file.close();

		return true;
	}
	catch (const exception& e) {
		cout << "Exception at saveToMeFile(): " << e.what() << endl;
		return false;
	}
}

// save file in bytes - using file path and the file content
// return true on sucsses
bool FileHandler::writeBinaryFile(string filePath, string content) {
	try {
		ofstream file(filePath, ifstream::binary);
		file << content;
		file.close();
		return true;
	}
	catch (const exception& e) {
		cout << "Exception at saveFile(): " << e.what() << endl;
		return false;
	}
}

// read file in bytes - using file path
// read at most bytes from file
// return file content
bool FileHandler::readBinaryFile(ifstream& myFile, char* const buffer,uint32_t bytes) {
	try {
		if (buffer == nullptr || bytes == 0)
			return false;

		myFile.read(buffer, bytes);

		return true;
	}
	catch (const exception& e) {
		cout << "Exception at readFile(): " << e.what() << endl;
		return false;
	}
}

// get any file size - support large files 
long long FileHandler::getFileSize(string filePath) {
	ifstream is(filePath, ifstream::binary);

	is.seekg(0, is.end);
	long long length = is.tellg();

	return length;
}
