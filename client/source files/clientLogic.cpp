#include "clientLogic.h"
#include <iostream>
#include <iomanip>

// entry point for client,
// if me.info exist request reconnect else request registration,
// exchange AES key and send an encrypted file to server
void ClientLogic::startClient() {
	string transfer[3];
	string me[3];

	ifstream transferFile("transfer.info");
	fileHandler.readFromInfo(transferFile, transfer);
	transferFile.close();

	string host = transfer[0].substr(0, transfer[0].find(":"));
	string port = transfer[0].substr(transfer[0].find(":") + 1);

	boost::asio::io_context io_context;
	tcp::socket sock(io_context);
	tcp::resolver resolver(io_context);
	
	ifstream meFile("me.info", ifstream::binary);
	// if file exist try reconnecting to host 
	if (fileHandler.readFromInfo(meFile, me)) {
		// send reconnect request
		connectToHost(sock, resolver, host, port);
		requestReconnect(sock, me[0], me[1]);
		Response* response = receiveResponse(sock);

		// handle the response 
		if (response->code == responseCode::RECONNECT_APPROVE && response->payloadSize == AES_KEY_RECEIVED) {

			// load the private RSA key from file
			if (!RSA.loadFromFile()) {
				cout << "Can't load private RSA key from file" << endl;
				delete response;
				meFile.close();
				sock.close();
				return;
			}

			// fetch the AES key from the response payload  
			string AESkey = organizeResponseAES(response->payload, (uint8_t*)me[1].c_str());

			// save the new AES key to me.info
			fileHandler.wirteToMeFile(me[0], (uint8_t*)me[1].c_str(), AESkey);

			// (*) I have written two file into transfer.info for registration and reconnect,
			// because the server dosen't allow two files with the same name for the same client 
			string fileName = transfer[2].substr(transfer[2].find(",") + 1);
			// send encrypted file to server
			// handle CRC - send the file up to 3 times
			handleCRCRequest(sock, resolver, me[1], fileName, host, port, AESkey);
		}
		else {
			cout << "Server didn't send AES key" << endl;
			cout << "Or the length of the AES key is not 16 bytes" << endl;
		}
		delete response;
		meFile.close();
		sock.close();
	}
	// registration and sending public RSA key
	else {
		// send registration request 
		connectToHost(sock, resolver, host, port);
		requestRegistration(sock, transfer[1]);
		Response* response = receiveResponse(sock);

		// handle response
 		if (response->code != responseCode::REGISTRATION_SUCCESS) {
			if (response->code == responseCode::REGISTRATION_FAILED) {
				cout << "Registration failed, try changing the name in transfer.info" << endl;
			}
			else if (response->code == responseCode::GENERIC_ERROR) {
				cout << "Registration failed, the server has a generic error" << endl;
				cout << "Please try again later" << endl;
			}
			else {
				cout << "can't receive from server, socket error" << endl;
			}
			delete response;
			meFile.close();
			sock.close();
			return;
		}

		uint8_t clientId[CLIENT_ID_LEN + 1];
		clientId[CLIENT_ID_LEN] = '\0';
		memcpy(clientId, response->payload, CLIENT_ID_LEN);

		// send RSA request
		connectToHost(sock, resolver, host, port);
		requestRSA(sock, transfer[1], clientId);
		response = receiveResponse(sock);

		// handle response
		if (response->code == responseCode::RSA_KEY_RECEIVED && response->payloadSize == AES_KEY_RECEIVED) {

			// no need to load private RSA - no file yet, the RSA object already has the private key
			string AESkey = organizeResponseAES(response->payload, clientId);
			if (AESkey == "") {
				cout << "Can't extract AES key from payload" << endl;
				delete response;
				meFile.close();
				sock.close();
				return;
			}

			// write to me.info and priv.key
			if (!fileHandler.wirteToMeFile(transfer[1], clientId, AESkey) || !RSA.writeToFile()) {
				cout << "Can't save to file" << endl;
				delete response;
				meFile.close();
				sock.close();
				return;
			}

			cout << "Registration complited successfully" << endl;

			// convert unit8_t to string
			stringstream ss;
			ss << clientId;
			string clientIdStr = ss.str();

			// see comment (*) above 
			string fileName = transfer[2].substr(0, transfer[2].find(","));
			// send encrypted file to server
			// handle CRC - send the file up to 3 times
			handleCRCRequest(sock, resolver, clientIdStr, fileName, host, port, AESkey);
		}
		else {
			cout << "Server didn't send AES key" << endl;
			cout << "Or the length of the AES key is not 16 bytes" << endl;
		}
		delete response;
	}
	meFile.close();
	sock.close();
} 

// unpack the CRC response payload,
// handle CRC response - calculte checksum,
// check if the server's checksum is equal to the client checksum
bool ClientLogic::organizeResponseCRC(Response& response, string cid, string fname) {
	// check if file received successfully 
	if (response.code == responseCode::FILE_RECEIVED_SUCCESS) {

		// no need to check contect size - just ckecksum
		uint8_t* clientId = new uint8_t[CLIENT_ID_LEN + 1];
		clientId[CLIENT_ID_LEN] = '\0';
		uint8_t* fileName = new uint8_t[NAME_LEN + 1];
		fileName[NAME_LEN] = '\0';
		uint8_t* cksumServer = new uint8_t[CHECKSUM_LEN + 1];
		cksumServer[CHECKSUM_LEN] = '\0';
		uint8_t* buff = response.payload;
		memcpy(clientId, buff, CLIENT_ID_LEN);
		buff += CLIENT_ID_LEN + CHECKSUM_LEN;	// contect size length same as checksum
		memcpy(fileName, buff, NAME_LEN);
		buff += NAME_LEN;
		memcpy(cksumServer, buff, CHECKSUM_LEN);

		// calculating CRC
		int cksum = calculateCheckSum(fname);
		if (!cksum) {
			delete[] clientId;
			delete[] fileName;
			delete[] cksumServer;
			return false;
		}

		// convert int to bytes
		union {
			unsigned int integer;
			uint8_t byte[CHECKSUM_LEN];
		} cksumBytes;
		cksumBytes.integer = cksum;

		// check that the client id, file name and checksum are equal (server == client)
		if (memcmp(clientId, cid.c_str(), CLIENT_ID_LEN) || memcmp(cksumBytes.byte, cksumServer, CHECKSUM_LEN)
														 || memcmp(fileName, fname.c_str(), fname.length())) {
			cout << "The client id, file name or checksum dosen't match" << endl;
			delete[] clientId;
			delete[] fileName;
			delete[] cksumServer;
			return false;
		}
		return true;
	}
	else{
		cout << "The response code dosen't match the CRC ok request" << endl;
		cout << "Response code from server: " << response.code << endl;
		return false;
	}
}

// send the file to the server up to three times,
// check if the checksum from the server is equal to the check sum of the client,
// if not send two more times,
// if the checksums are equal send CRC ok request else send CRC not ok
void ClientLogic::handleCRCRequest(tcp::socket& sock, tcp::resolver& resolver, string cid, string fname, string host, string port, string AESkey) {
	// send file for the first time
	connectToHost(sock, resolver, host, port);
	requestSendFile(sock, fname, cid, AESkey);
	Response* response = receiveResponse(sock);

	int send = 1;
	// check if checksum from server is euqal to client checksum - send file up to 3 times
	while (!organizeResponseCRC(*response, cid, fname) && send < 3) {
		cout << "Something want wrong in CRC response" << endl;
		cout << "Sending the file for the " << send + 1 << " time..." << endl;

		// send CRC not ok to server
		connectToHost(sock, resolver, host, port);
		requestCRCok(sock, cid, fname, false);
		response = receiveResponse(sock);

		if (response->code != responseCode::MESSAGE_RECEIVED) {
			cout << "There is a problem with the server: response code not as expected" << endl;
			cout << "Response code from server: " << response->code << endl;
		}

		// send encrypted file to server
		connectToHost(sock, resolver, host, port);
		requestSendFile(sock, fname, cid, AESkey);
		response = receiveResponse(sock);

		send += 1;
	}
	if (send < 3) {
		// send CRC ok to server
		connectToHost(sock, resolver, host, port);
		requestCRCok(sock, cid, fname, true);
		response = receiveResponse(sock);
		if (response->code == responseCode::MESSAGE_RECEIVED && !memcmp(response->payload, cid.c_str(), CLIENT_ID_LEN)) 
			cout << "The file sent to the server successfully with CRC" << endl;
		else
			cout << "There was a problem with sending the file" << endl;
	}
	else {
		// send CRC not ok to server
		connectToHost(sock, resolver, host, port);
		requestCRCok(sock, cid, fname, false);
		response = receiveResponse(sock);
		if (response->code == responseCode::MESSAGE_RECEIVED && !memcmp(response->payload, cid.c_str(), CLIENT_ID_LEN))
			cout << "Problem with checksum or the file already exist on the server" << endl;
		else
			cout << "Generic error with server" << endl;
	}
}

// unpack AES response - handle the response
// check that the response sent to the right client,
// decrypt the AES key sent from the server (server sent the key as cipher)
// return a string representation of the key 
string ClientLogic::organizeResponseAES(uint8_t* payload, uint8_t* clientId) {
	string AESkey = "";
	uint8_t* temp = new uint8_t[CLIENT_ID_LEN + 1];
	temp[CLIENT_ID_LEN] = '\0';
	memcpy(temp, payload, CLIENT_ID_LEN);

	// check if the AES key received belongs to the client
	if (std::memcmp(clientId, temp, CLIENT_ID_LEN) != 0) {
		cout << "Error got the wrong AES key" << endl;
		return AESkey;
	}

	char* cipher = new char[CIPHER_SIZE + 1];
	cipher[CIPHER_SIZE] = '\0';
	temp = payload;

	// move the pointer to the start of the AES key 
	temp += CLIENT_ID_LEN;
	memcpy(cipher, temp, CIPHER_SIZE);
	AESkey = RSA.decrypt(cipher, CIPHER_SIZE);

	// check if decrypt() got the AES key
	if (AESkey == "") {
		cout << "Can't decrept the cipher" << endl;
	}

	memset(temp, 0, CLIENT_ID_LEN);
	return AESkey;
}

// send CRC ok or not ok request to server,
// if CRC_OK is true, send CRC ok, else send CRC not ok
void ClientLogic::requestCRCok(tcp::socket& sock, string cliendId, string fileName, bool CRC_OK) {
	// create request 1104 or 1105 - CRC_OK == true for 1104
	Request* request = new Request();
	memcpy(request->clientId, cliendId.c_str(), CLIENT_ID_LEN);

	if (CRC_OK)
		request->code = requestCode::CRC_OK;
	else
		request->code = requestCode::CRC_NOT_OK;

	request->payloadSize = NAME_LEN;
	request->payload = new uint8_t[NAME_LEN + 1];
	request->payload[NAME_LEN] = '\0';
	memset(request->payload, 0, NAME_LEN);
	memcpy(request->payload, fileName.c_str(), fileName.length());

	// send request 
	sendRequest(sock, *request);

	// make sure no one can use the data
	memset(request->payload, 0 , NAME_LEN);
	delete[] request->payload;
	memset(request, 0, sizeof(request));
	delete request;
}

// send file request - send an encrypted file to server,
// using the AES key the server sent
void ClientLogic::requestSendFile(tcp::socket& sock, string filePath, string clientId, string key) {
	// key length (16 bytes) was verified by RSA_KEY_RECEIVED_LEN in startClient()
	unsigned char ref[AES_KEY_LEN];
	memcpy(ref, key.c_str(), AES_KEY_LEN);
	AES.loadKey(ref);

	// read a chunk from the file 
	int length = fileHandler.getFileSize(filePath);
	
	// create the first pakect with header  
	// get cipher size
	uint32_t cipherSize = length;

	while (cipherSize % 16 != 0) 
		cipherSize++;

	string fileNameStr = filePath.substr(filePath.find_last_of("/\\") + 1);
	// 255 bytes
	uint8_t* fileName = createName(fileNameStr);

	// orginaize payload
	uint8_t* payload = new uint8_t[PACKET_SIZE];
	uint8_t* ptr = payload;
	memcpy(ptr, &cipherSize, sizeof(cipherSize));
	ptr += sizeof(cipherSize);
	memcpy(ptr, fileName, NAME_LEN);
	ptr += NAME_LEN;

	// message content should be zeros in the first packet 
	memset(ptr, 0, PACKET_SIZE - (NAME_LEN + sizeof(cipherSize)));

	// create send file request
	Request* request = new Request();
	memcpy(request->clientId, clientId.c_str(), CLIENT_ID_LEN);
	request->code = requestCode::SEND_FILE;
	request->payloadSize = sizeof(cipherSize) + NAME_LEN;;
	request->payload = payload;

	// create first request to send
	uint8_t* buffer = new uint8_t[PACKET_SIZE];
	memset(buffer, 0, PACKET_SIZE);
	createRequest(*request, buffer);

	// send first packet of send file request,
	// Header, payload = cipher length and file name
	socketHandler.sendMassage(sock, buffer);

	// send the file by chunks - support large files
	string cipher;
	char* chunk = new char[PACKET_SIZE];
	ifstream myFile(filePath, ifstream::binary);

	// number of bytes from file 
	int bytesSent = 0;

	while (length > bytesSent) {

		// read a chunk of 1024 bytes from the file
		if (!fileHandler.readBinaryFile(myFile, chunk, PACKET_SIZE)) {
			cout << "Can't read file " << filePath << endl;
			return;
		}
		// encrypt the chunk
		if (length - bytesSent > PACKET_SIZE) {
			cipher = AES.encrypt(chunk, PACKET_SIZE);
			memcpy(buffer, cipher.c_str(), PACKET_SIZE);
			cipherSize -= PACKET_SIZE;
		}
		else {
			cipher = AES.encrypt(chunk, (length - bytesSent));
			memcpy(buffer, cipher.c_str(), cipherSize);
		}

		// send the chunk 
		socketHandler.sendMassage(sock, buffer);
		bytesSent += PACKET_SIZE;
	}

	// make sure no one can use the data
	memset(ref, 0, AES_KEY_LEN);
	memset(request, 0, sizeof(request));
	delete request;
	memset(payload, 0, PACKET_SIZE);
	delete[] payload;
	memset(buffer, 0, PACKET_SIZE);
	delete[] buffer;
	memset(chunk, 0, PACKET_SIZE);
	delete[] chunk;
	ptr = nullptr;
}

// send a reconnect request to server using the client name 
void ClientLogic::requestReconnect(tcp::socket& sock, string name, string clientId) {
	// create reconnect request
	Request* request = new Request();
	memcpy(request->clientId, clientId.c_str(), CLIENT_ID_LEN);
	request->code = requestCode::CONNECT_AGAIN;

	//create a name length 255 bytes
	uint8_t* clientName = createName(name);
	request->payloadSize = NAME_LEN;
	request->payload = clientName;

	sendRequest(sock , *request);

	memset(request, 0, sizeof(request));
	delete request;
}

// generate RSA keys (public and private) and send the public key to the server
void ClientLogic::requestRSA(tcp::socket& sock, string name, uint8_t* clientId) {
	if (!RSA.generateKeys()) {
		cout << "Can't generate RSA keys" << endl;
		exit(EXIT_FAILURE);
	}
	string publicKey = RSA.getPublicKey();

	//create RSA request
	Request* request = new Request();
	memcpy(request->clientId, clientId, CLIENT_ID_LEN);
	request->code = requestCode::SEND_RSA_KEY;
	//create a name length 255 bytes
	uint8_t* clientName = createName(name);

	// create payload of SEND_RSA_KEY
	uint32_t payloadSize = NAME_LEN + PUBLIC_KEY_LEN;
	uint8_t* payload = new uint8_t[payloadSize];
	uint8_t* ptr = payload;
	memcpy(ptr, clientName, NAME_LEN);
	ptr += NAME_LEN;
	memcpy(ptr, publicKey.c_str(), PUBLIC_KEY_LEN);
	request->payloadSize = payloadSize;
	request->payload = payload;

	sendRequest(sock , *request);

	memset(request, 0, sizeof(request));
	delete request;
	memset(payload, 0, payloadSize);
	delete[] payload;
}

// send registration request to server using the client name from transfer.info file
void ClientLogic::requestRegistration(tcp::socket& sock, string name) {
	// create request for registration
	Request* request = new Request();
	request->code = requestCode::REGISTRATION;

	//create a name length 255 bytes
	uint8_t* payload = createName(name);
	request->payloadSize = NAME_LEN;
	request->payload = payload;

	sendRequest(sock , *request);

	memset(request, 0, sizeof(request));
	delete request;
}

// receive the response from the server - receive all packets
// arrange the packets from server as a Response object and return it
ClientLogic::Response* ClientLogic::receiveResponse(tcp::socket& sock) {
	uint8_t* buffer = new uint8_t[PACKET_SIZE];
	memset(buffer, 0, PACKET_SIZE);
	const uint8_t* buffPtr = buffer;
	if (!socketHandler.receiveMassage(sock, buffer))
		return new Response();
	
	// organize the first packet as a Response object
	Response* response = new Response();
	uint32_t responseHeaderLen = response->headerSize();
	memcpy(response, buffPtr, responseHeaderLen);
	buffPtr += responseHeaderLen;

	// if there is no payload, return the response with only the header  
	if (response->code == responseCode::REGISTRATION_FAILED || response->code == responseCode::GENERIC_ERROR) 
		return response;
	
	// set memory for payload
	response->payload = new uint8_t[response->payloadSize + 1];
	response->payload[response->payloadSize] = '\0';
	uint32_t leftover = PACKET_SIZE - responseHeaderLen;

	if (leftover > response->payloadSize) {
		memcpy(response->payload, buffPtr, response->payloadSize);
		// make sure no one can use the buffer data
		memset(buffer, 0, PACKET_SIZE);
		delete[] buffer;
		buffPtr = nullptr;

		return response;
	}

	// get the rest of the packets 
	uint8_t* payloadPtr = response->payload;
	memcpy(payloadPtr, buffPtr, leftover);
	payloadPtr += leftover;
	uint32_t remain = response->payloadSize - leftover;
	while (remain > 0) {
		if (!socketHandler.receiveMassage(sock, buffer)) {
			memset(buffer, 0, PACKET_SIZE);
			delete[] buffer;
			buffPtr = nullptr;
			payloadPtr = nullptr;
			return NULL;
		}
		if (remain > PACKET_SIZE) {
			memcpy(payloadPtr, buffer, PACKET_SIZE);
			remain -= PACKET_SIZE;
			payloadPtr += PACKET_SIZE;
		}
		else {
			memcpy(payloadPtr, buffer, remain);
			remain = 0 ;
		}
	}

	// make sure no one can use the buffer data
	memset(buffer, 0, PACKET_SIZE);
	delete[] buffer;
	buffPtr = nullptr;
	payloadPtr = nullptr;

	return response;
}

// create the first pakcet of any request - header and some payload
// buffer will by a single pakect - 1024 bytes 
void ClientLogic::createRequest(const Request& request, uint8_t* buffer) {
	uint8_t* ptr = buffer;
	uint32_t remain = PACKET_SIZE - request.headerSize();

	if (request.payloadSize < remain)
		remain = request.payloadSize;

	memcpy(ptr, &(request.clientId), sizeof(request.clientId));
	ptr += sizeof(request.clientId);
	memcpy(ptr, &(request.version), sizeof(request.version));
	ptr += sizeof(request.version);
	memcpy(ptr, &(request.code), sizeof(request.code));
	ptr += sizeof(request.code);
	memcpy(ptr, &(request.payloadSize), sizeof(request.payloadSize));
	ptr += sizeof(request.payloadSize);
	memcpy(ptr, request.payload, remain);

	// make sure no one can use the ptr 
	ptr = nullptr;
}

// send a request to server - use sendAll to send large payloads
void ClientLogic::sendRequest(tcp::socket& sock, const Request& request) {
	uint8_t* buffer = new uint8_t[PACKET_SIZE];
	memset(buffer, 0, PACKET_SIZE);
	createRequest(request, buffer);

	if (sendAll(sock, buffer, request)) {
		cout << "Request sent to server successfully" << endl;
	}
	else {
		cout << "Failed to sent request on socket" << endl;
		sock.close();
		exit(EXIT_FAILURE);
	}
	// make sure no one can use the buffer or request
	memset(buffer, 0, PACKET_SIZE);
	delete[] buffer;
}

// send the entire request - support large payloads
// buffer will by a single pakect - 1024 bytes 
bool ClientLogic::sendAll(tcp::socket& sock, uint8_t* buffer, Request request) {

	if (!socketHandler.sendMassage(sock, buffer))
		return false;

	// send the remain of the payload - if there is a remain
	uint32_t bytesSent = PACKET_SIZE - request.headerSize();
	uint8_t* tmp = request.payload;
	tmp += bytesSent;
	while (bytesSent < request.payloadSize) {
		if (request.payloadSize - bytesSent > PACKET_SIZE) {
			memcpy(buffer, tmp, PACKET_SIZE);
			bytesSent += PACKET_SIZE;
			tmp += PACKET_SIZE;
		}
		else {
			memcpy(buffer, tmp, (request.payloadSize - bytesSent));
			bytesSent += (request.payloadSize - bytesSent);
			tmp += (request.payloadSize - bytesSent);
		}

		if (!socketHandler.sendMassage(sock, buffer))
			return false;
	}
	// make sure no one can use the tmp
	tmp = nullptr;
	return true;
}

// create a payload of client or file name,
// length of 255 bytes null terminated
uint8_t* ClientLogic::createName(string name) {
	// name (client or file) 255 bytes, null terminated
	if (name.length() > 254) {
		cout << "The name needs to be up to 255 chars" << endl;
		cout << "Please change the name in transfer.info file" << endl;
		exit(EXIT_FAILURE);
	}
	uint8_t* payload = new uint8_t[NAME_LEN];
	memset(payload, 0, NAME_LEN);
	payload[NAME_LEN - 1] = '\0';
	memcpy(payload, name.c_str(), name.length());

	return payload;
}

// calculate checksum - hex number with cksum()
// than split this number to chunks (8 of them),
// and calculate the sum of those chunks so they can fit into 4 bytes
int ClientLogic::calculateCheckSum(string filePath) {
	// calculating CRC like linux
	const int chunkSize = 4;
	char* checkSum = new char[(MD5LEN * 2) + 1];
	checkSum[MD5LEN * 2] = '\0';

	char* chunk = new char[chunkSize + 1];
	chunk[chunkSize] = '\0';
	char* ptr = checkSum;

	int ans = 0;
	if (cksum.cksum(filePath, checkSum)) {
		cout << "Someting went wrong calculting checksum" << endl;
		return ans;
	}

	// clculating the sum of the hex number (32 chars - 16 bytes),
	// so it can be stored in 4 bytes - by chunks
	string s;
	for (int i = 0; i < (chunkSize * 2); i++) {
		memcpy(chunk, ptr, chunkSize);
		ptr += chunkSize;
		s = chunk;
		ans += stoi(s, 0, 16);
	}

	memset(checkSum, 0 , (MD5LEN * 2));
	delete[] checkSum;
	memset(chunk, 0, chunkSize);
	delete[] chunk;
	return  ans;
}

// connect to host using socket, host and port
// if can't connect exit with error (-1)
void ClientLogic::connectToHost(tcp::socket& sock, tcp::resolver& resolver, string host, string port) {
	try {
		boost::asio::connect(sock, resolver.resolve(host, port));
	}
	catch (const exception& e) {
		cout << "Error: can't connect to host - " << endl;
		cout << e.what() << endl;;
		sock.close();
		exit(EXIT_FAILURE);
	}
}
