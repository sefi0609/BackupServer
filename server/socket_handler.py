import socket

PACKET_SIZE = 1024
HOST = '127.0.0.1'  # can be '' as well


# SocketHandler class - handel the server and client sockets
class SocketHandler:
    def __init__(self, port):
        self.host = HOST
        self.port = port
        self.client_sock = socket.socket()
        self.client_addr = ''

    # create server socket and wait for client connection,
    # save to class client socket and address,
    # after the connection is established - no need to save server socket, just close it
    def wait_for_client_socket(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((self.host, self.port))
            s.listen()
            self.client_sock, self.client_addr = s.accept()
            s.close()
        except Exception as e:
            print(f'Wait_for_client_socket: {e}')
            self.close_socket()

    # close the client's socket
    def close_socket(self):
        print(f'Closing socket, client at address: {self.client_addr}')
        self.client_sock.close()

    # send a packet of length PACKET_SIZE to the client,
    # if the data to be sent is smaller than PACKET_SIZE ped it with zeros
    def send_to_client(self, massage):
        # make sure massage is size PACKET_SIZE
        bytes_size = len(massage)
        if bytes_size < PACKET_SIZE:
            massage += bytearray(PACKET_SIZE - bytes_size)
        try:
            self.client_sock.sendall(massage)
        except Exception as e:
            print(f'send_to_client: {e}')

    # receive a packet from client of PACKET_SIZE length
    def receive_from_client(self):
        try:
            return self.client_sock.recv(PACKET_SIZE)
        except Exception as e:
            print(f'receive_from_client: {e}')
