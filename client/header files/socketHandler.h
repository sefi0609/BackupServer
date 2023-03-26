#pragma once
#include <iostream>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio.hpp>

#define PACKET_SIZE 1024

using boost::asio::ip::tcp;
using namespace std;

class SocketHandler {
public:
	bool sendMassage(tcp::socket& sock, const uint8_t* buff);
	bool receiveMassage(tcp::socket& sock, uint8_t* buff);
};