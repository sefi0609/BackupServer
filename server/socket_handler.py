import socket

PACKET_SIZE = 1024
HOST = '127.0.0.1'  # can be '' as well


class SocketHandler:
    """ SocketHandler class - handel the server and client sockets """
    def __init__(self, port):
        self.host = HOST
        self.port = port
        self.client_sock = socket.socket()
        self.client_addr = ''

    def wait_for_client_socket(self):
        """
        Create server socket and wait for client connection,
        save to class client socket and address,
        after the connection is established - no need to save server socket, just close it
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind((self.host, self.port))
                sock.listen()
                self.client_sock, self.client_addr = sock.accept()
        except Exception as e:
            print(f'Wait_for_client_socket: {e}')
            self.close_socket()

    def close_socket(self):
        """ Close the client's socket """
        print(f'Closing socket, client at address: {self.client_addr}')
        self.client_sock.close()

    def send_to_client(self, massage):
        """
        send a packet of length PACKET_SIZE to the client,
        if the data to be sent is smaller than PACKET_SIZE ped it with zeros
        """
        # make sure massage is size PACKET_SIZE
        bytes_size = len(massage)
        if bytes_size < PACKET_SIZE:
            massage += bytearray(PACKET_SIZE - bytes_size)
        try:
            self.client_sock.sendall(massage)
        except Exception as e:
            print(f'send_to_client: {e}')

    def receive_from_client(self):
        """ receive a packet from client of PACKET_SIZE length """
        try:
            return self.client_sock.recv(PACKET_SIZE)
        except Exception as e:
            print(f'receive_from_client: {e}')
