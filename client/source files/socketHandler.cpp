#include "socketHandler.h"

// send a packet PACKET_SIZE length the server using boost library
// sent buff - representation of packet, return true on sucsses 
bool SocketHandler::sendMassage(tcp::socket& sock, const uint8_t* buff) {
    try {
        boost::asio::write(sock, boost::asio::buffer(buff, PACKET_SIZE));
        return true;
    }
    catch (const exception& e) {
        cout << e.what() << endl;
        return false;
    }
}

// receive a packet PACKET_SIZE length from the server using boost library
// save the packet to buff, return true on sucsses 
bool SocketHandler::receiveMassage(tcp::socket& sock, uint8_t* buff) {
    try {
        memset(buff, 0, PACKET_SIZE);
        boost::asio::read(sock, boost::asio::buffer(buff, PACKET_SIZE));
        return true;
    }
    catch (const exception& e) {
        cout << e.what() << endl;
        return false;
    }
}
