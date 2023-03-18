#pragma once
#include "socketHandler.h"
#include "fileHandler.h"
#include "cryptoHandler.h"
#include "checkSum.h"
#include <sstream>

#define VERSION 3
#define CLIENT_ID_LEN 16
// the same for client name and file name 
#define NAME_LEN 255
#define CHECKSUM_LEN 4
#define EXIT_FAILURE -1

using boost::asio::ip::tcp;
using namespace std;
using std::memcpy; 
using std::memset; 

class ClientLogic {
public:
    void startClient();
private:
    struct Request {
#pragma pack(push, 1) 
        uint8_t clientId[CLIENT_ID_LEN] = { 0 };
        const uint8_t version = VERSION;
        uint16_t code = 0;
        uint32_t payloadSize = 0;
        uint8_t* payload = nullptr;
#pragma pack(pop)
        // size without payload
        uint32_t headerSize() const { return (sizeof(clientId) + sizeof(version) + sizeof(code) + sizeof(payloadSize)); }
    };

    struct Response {
#pragma pack(push, 1) 
        uint8_t version = 0;
        uint16_t code = 0;
        uint32_t payloadSize = 0;
        uint8_t* payload = nullptr;
#pragma pack(pop)
        // size without payload
        uint32_t headerSize() const { return (sizeof(version) + sizeof(code) + sizeof(payloadSize)); }
    };

    enum requestCode {
        REGISTRATION = 1100, SEND_RSA_KEY = 1101, CONNECT_AGAIN = 1102,
        SEND_FILE = 1103, CRC_OK = 1104, CRC_NOT_OK = 1105, CRC_FAILED = 1106
    };

    enum responseCode {
        REGISTRATION_SUCCESS = 2100, REGISTRATION_FAILED = 2101, RSA_KEY_RECEIVED = 2102,
        FILE_RECEIVED_SUCCESS = 2103, MESSAGE_RECEIVED = 2104, RECONNECT_APPROVE = 2105,
        RECONNECT_DENIED = 2106, GENERIC_ERROR = 2107
    };

    // to check that the key is 16 bytes,
    // the payload is client id and AES key(cipher) - 32 + 128
    #define AES_KEY_RECEIVED 144

    AESKey AES;
    RSAkeys RSA;
    CheckSum cksum;
    FileHandler fileHandler;
    SocketHandler socketHandler;
    uint8_t* createName(string name);
    int calculateCheckSum(string filePath);
    Response* receiveResponse(tcp::socket& sock);
    void requestRegistration(tcp::socket& sock, string name);
    void sendRequest(tcp::socket& sock, const Request& request);
    void createRequest(const Request& request, uint8_t* buffer);
    string organizeResponseAES(uint8_t* payload, uint8_t* clientId);
    bool sendAll(tcp::socket& sock, uint8_t* buffer, Request request);
    void requestRSA(tcp::socket& sock, string name, uint8_t* clientId);
    bool organizeResponseCRC(Response& response, string cid, string fname);
    void requestReconnect(tcp::socket& sock, string name, string clientId);
    void requestCRCok(tcp::socket& sock, string cliendId, string fileName, bool CRC_OK);
    void requestSendFile(tcp::socket& sock, string filePath, string clientId, string key);
    void connectToHost(tcp::socket& sock, tcp::resolver& resolver, string host, string port);
    void handleCRCRequest(tcp::socket& sock, tcp::resolver& resolver, string cid, string fname, string host, string port, string AESkey);
};