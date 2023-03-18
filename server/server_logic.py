import uuid
import time
import struct
import hashlib
import threading
from datetime import datetime
from file_handler import write_file, read_info
from database_handler import DataBase
from crypto_handler import CryptoHandler
from socket_handler import SocketHandler, PACKET_SIZE
# all the magic numbers in this script designed to confuse the enemy
# you can easily understand those numbers from the protocol in maman15
# most of them are indexes

# global variables and structs
RESPONSE_HEADER_LEN = 7

# 16 bytes for client id - hex representation
REQUEST_HEADER_LEN = 23
CLIENT_ID_LEN = 16

# the same for client name and file name
NAME_LEN = 255
VERSION = 3

# request 1103 content size 4 bytes
CONTENT_SIZE = 4
database = DataBase()
clients_table, files_table = database.get_tables()

# locks
db_lock = threading.Lock()
clients_lock = threading.Lock()
files_lock = threading.Lock()

response_code = {'REGISTRATION_SUCCESS': 2100, 'REGISTRATION_FAILED': 2101, 'RSA_KEY_RECEIVED': 2102,
                 'FILE_RECEIVED_SUCCESS': 2103, 'MESSAGE_RECEIVED': 2104, 'RECONNECT_APPROVE': 2105,
                 'RECONNECT_DENIED': 2106, 'GENERIC_ERROR': 2107}

request_code = {'REGISTRATION': 1100, 'SEND_RSA_KEY': 1101, 'CONNECT_AGAIN': 1102,
                'SEND_FILE': 1103, 'CRC_OK': 1104, 'CRC_NOT_OK': 1105, 'CRC_FAILED': 1106}


# class representation of response per maman15
class Response:
    def __init__(self):
        self.version = VERSION
        self.code = 0
        self.payload_size = 0
        self.payload = b''

    # pack the first packet
    def pack(self):
        leftover = PACKET_SIZE - RESPONSE_HEADER_LEN
        if self.payload_size < leftover:
            leftover = self.payload_size
        return struct.pack(f'<BHI{leftover}s', self.version, self.code, self.payload_size, self.payload[:leftover])


# class representation of request per maman15
class Request:
    def __init__(self, data):
        self.client_id = 0
        self.version = 0
        self.code = 0
        self.payload_size = 0
        self.payload = b''

        # unpack the request from the client
        try:
            self.client_id, self.version, self.code, self.payload_size = struct.unpack(
                '<16sBHI', data[:REQUEST_HEADER_LEN])
            leftover = PACKET_SIZE - REQUEST_HEADER_LEN
            if self.payload_size < leftover:
                leftover = self.payload_size
            self.payload = struct.unpack(f'<{leftover}s', data[REQUEST_HEADER_LEN: REQUEST_HEADER_LEN + leftover])
            self.payload = self.payload[0]
        except Exception as e:
            print(f'Error unpacking the request form the client: {e}')


# send a generic error response
def generic_error(sock):
    response = Response()
    response.code = response_code['GENERIC_ERROR']
    sock.send_to_client(response.pack())


# This is the Linux way to calculate check sum - using hash function (md5)
# then calculate chunks sum to fit in 4 bytes
def file_checksum(filename, read_chunk_size=65536, algorithm='md5'):
    checksum = hashlib.new(algorithm)  # Raises appropriate exceptions.
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(read_chunk_size), b''):
            checksum.update(chunk)
            # Release green-thread, if green-threads are not used it is a noop.
            time.sleep(0)
    checksum = checksum.hexdigest()

    # need to send 4 bytes
    hex_sum = 0
    chunk = 4
    while chunk <= len(checksum):
        hex_sum += int(checksum[chunk - 4:chunk], 16)
        chunk += 4
    return hex_sum


# receive all the packet from the client - arrange them into Request object
# produce the time of the request for the database
# call check_code() to continue to the proper function (by request)
# after handling the request close the client socket
def get_all_packets(sock):
    data = []
    request = Request(sock.receive_from_client())

    # save the request time
    now = datetime.now()
    last_seen = now.strftime("%d/%m/%Y %H:%M:%S")

    # get all the extra packets (if there are any)
    payload_size_header = PACKET_SIZE - REQUEST_HEADER_LEN
    while payload_size_header < request.payload_size:
        data.append(sock.receive_from_client())
        payload_size_header += PACKET_SIZE

    # (1) for this two request the payload can't be decoded,
    # payload process will be implemented in the requests functions
    if request.code != request_code['SEND_RSA_KEY'] and request.code != request_code['SEND_FILE']:
        payload = request.payload.decode().strip('\0')
    else:
        payload = request.payload

    # unpack all the extra packets
    remain = request.payload_size - len(request.payload)
    for packet in data:
        if remain < PACKET_SIZE:
            temp = struct.unpack(f'<{remain}s', packet[:remain])
        else:
            temp = struct.unpack(f'<{PACKET_SIZE}s', packet)
            remain -= PACKET_SIZE

        # see (1) above
        if request.code != request_code['SEND_RSA_KEY'] and request.code != request_code['SEND_FILE']:
            payload += temp[0].decode().strip('\0')
        else:
            payload += temp[0]

    request.payload = payload
    check_code(request, sock, last_seen)
    sock.close_socket()


# send all packets to client using Response object,
# make sure all the payload sent to the client
def send_all_packets(sock, response):
    sock.send_to_client(response.pack())
    payload_sent = PACKET_SIZE - RESPONSE_HEADER_LEN
    remain = response.payload_size - payload_sent

    # send the extra packets
    while remain > 0:
        if remain > PACKET_SIZE:
            temp = struct.pack(f'<{PACKET_SIZE}s', response.payload[payload_sent:payload_sent + PACKET_SIZE])
            sock.send_to_client(temp)
            remain -= PACKET_SIZE
            payload_sent += PACKET_SIZE
        else:
            temp = struct.pack(f'<{remain}s', response.payload[payload_sent:payload_sent + remain])
            sock.send_to_client(temp)
            remain = 0


# check the request code and call the proper function
# update database and memory
def check_code(request, sock, last_seen):
    global database, clients_table

    if request.code == request_code['REGISTRATION']:
        registration_request(request, sock, last_seen)
    elif request.code == request_code['SEND_RSA_KEY']:
        rsa_request(request, sock, last_seen)
    elif request.code == request_code['CONNECT_AGAIN']:
        reconnect_request(request, sock, last_seen)
    elif request.code == request_code['SEND_FILE']:
        send_file_request(request, sock, last_seen)
    elif request.code == request_code['CRC_OK']:
        crc_request(request, sock, last_seen, True)
    elif request.code == request_code['CRC_NOT_OK']:
        crc_request(request, sock, last_seen, False)
    elif request.code == request_code['CRC_FAILED']:
        crc_request(request, sock, last_seen, False)
    else:
        generic_error(sock)
        print('Not a valid request code')


# handle CRC request,
# crc_ok true - CRC is ok, else CRC is not ok
# update database and memory
def crc_request(request, sock, last_seen, crc_ok):
    global clients_table, files_table, database

    # check that the client is registered
    ref = False
    # make sure no thread is using the clients tables in memory
    with clients_lock:
        for client in clients_table:
            if request.client_id == client[0]:
                ref = True

    if ref:
        ref = False
        # make sure no thread is using the files tables in memory
        with files_lock:
            # check that the client sent this file
            for file in files_table:
                if request.client_id == file[0] and request.payload == file[1]:
                    ref = True
                    file_name = file[1]
    try:
        if crc_ok:
            # update databases and memory
            # save to shared resources as quickly as possible
            # if statement will prevent deadlock
            while True:
                if not (db_lock.locked() or clients_lock.locked() or files_lock.locked()):
                    with db_lock, clients_lock, files_lock:
                        database.update_files(1, request.client_id, file_name, last_seen)
                        clients_table, files_table = database.get_tables()
                    break
                time.sleep(1)
        else:
            while True:
                if not (db_lock.locked() or clients_lock.locked()):
                    with db_lock, clients_lock:
                        database.update_last_seen(last_seen, request.client_id)
                        clients_table = database.get_clients_table()
                    break
                time.sleep(1)
    except Exception as e:
        generic_error(sock)
        print(f"Can't update database or memory: {e}")
        return

    # send response
    if ref:
        response = Response()
        response.code = response_code['MESSAGE_RECEIVED']
        response.payload_size = CLIENT_ID_LEN
        response.payload = request.client_id
        send_all_packets(sock, response)
    else:
        generic_error(sock)
        print("The client is not registered or the file doesn't exist")
        return


# handle send file request,
# get the AES key from memory,
# decrypt the file sent by the client as cipher,
# write the file to the correct path - files/client_name/file_name,
# calculate checksum and create a response for client,
# update database and memory
def send_file_request(request, sock, last_seen):
    global clients_table, files_table, database

    # check if the client is registered
    aes_key = None
    # lock the clients table in memory
    with clients_lock:
        for client in clients_table:
            if client[0] == request.client_id:
                client_name = client[1]
                aes_key = client[4][:16]    # extract the key without the salt
                # in a real life project this comment will not be written

    response = Response()
    aes = CryptoHandler(None, aes_key)
    if aes_key:
        file_size = struct.unpack(f'<i', request.payload[:CONTENT_SIZE])
        file_size = file_size[0]
        file_name = request.payload[CONTENT_SIZE:CONTENT_SIZE + NAME_LEN].decode().strip('\0')
        cipher = request.payload[CONTENT_SIZE + NAME_LEN:]
        if file_size != len(cipher):
            generic_error(sock)
            print("Error: the cipher size doesn't match")
            return

        # update files table and memory,
        # if file is already in the database send generic error
        try:
            while True:
                if not (db_lock.locked() or clients_lock.locked() or files_lock.locked()):
                    with db_lock, clients_lock, files_lock:
                        # 0 - not verified yet
                        database.save_to_files(request.client_id, file_name,
                                               f'files/{client_name}/{file_name}', 0, last_seen)
                        clients_table, files_table = database.get_tables()
                    break
                time.sleep(1)
        except Exception as e:
            generic_error(sock)
            print(f"Can't update database or memory: {e}")
            return

        # decrypt file and save it to the right path
        plaintext = aes.decrypt(cipher)
        write_file(client_name, file_name, plaintext)
        check_sum = file_checksum(f'files/{client_name}/{file_name}')

        # pack the payload for FILE_RECEIVED_SUCCESS response
        payload = struct.pack(f'<{CLIENT_ID_LEN}si{NAME_LEN}si',
                              request.client_id, file_size, file_name.encode(), check_sum)
        response.code = response_code['FILE_RECEIVED_SUCCESS']
        response.payload_size = CLIENT_ID_LEN + CONTENT_SIZE + NAME_LEN + CONTENT_SIZE
        response.payload = payload

        # send response
        send_all_packets(sock, response)
    else:
        generic_error(sock)
        print("Error: the client is not registered")
        return


# handle reconnect request from client,
# get the public key of the client - if registered,
# generate new AES key, encrypt it and send to client
# update new AES key in memory and database
def reconnect_request(request, sock, last_seen):
    global clients_table, database

    public_key = None
    # check if the client is registered, lock the table
    with clients_lock:
        for client in clients_table:
            if client[0] == request.client_id and client[1] == request.payload:
                public_key = client[2]

    # if the client is registered create new AES key
    response = Response()
    if public_key:
        rsa = CryptoHandler(public_key)
        cipher_key = rsa.get_aes_key()
    else:
        response.code = response_code['RECONNECT_DENIED']
        response.payload = request.client_id
        response.payload_size = CLIENT_ID_LEN
        send_all_packets(sock, response)
        print('Client is not in the data base')
        return

    # if key decrypted successfully send RECONNECT_APPROVE response
    if cipher_key:
        # update database and memory
        try:
            while True:
                if not (db_lock.locked() or clients_lock.locked()):
                    with db_lock, clients_lock:
                        rsa.update_db(last_seen, request.client_id, database)
                        clients_table = database.get_clients_table()
                    break
                time.sleep(1)
        except Exception as e:
            generic_error(sock)
            print(f'Exception at reconnect_request(): {e}')
            return

        response.code = response_code['RECONNECT_APPROVE']
        response.payload = request.client_id + cipher_key
        response.payload_size = len(response.payload)

        # send response
        send_all_packets(sock, response)
    else:
        generic_error(sock)
        print("Internal error: Can't decrypt the AES key")


# handle RSA request from client,
# receive the client's public key, generate an AES key,
# encrypt the AES key with the client public key,
# send the cipher key to the client,
# update the new AES key to the database
def rsa_request(request, sock, last_seen):
    global clients_table, database

    # get the client name from the payload
    client_name = request.payload[:NAME_LEN].decode().strip('\0')
    public_key = request.payload[NAME_LEN:]

    # verify that the client is register to the server
    ref = False
    with clients_lock:
        for client in clients_table:
            if client[0] == request.client_id and client[1] == client_name:
                ref = True

    if ref:
        rsa = CryptoHandler(public_key)
        # get the AES key and save the keys to the database
        cipher_key = rsa.get_aes_key()
    else:
        generic_error(sock)
        print("Error: the client is not registered")
        return

    if cipher_key:
        # update database and memory
        try:
            while True:
                if not (db_lock.locked() or clients_lock.locked()):
                    with db_lock, clients_lock:
                        rsa.save_to_db(request.client_id, client_name, last_seen, database)
                        clients_table = database.get_clients_table()
                    break
                time.sleep(1)
        except Exception as e:
            generic_error(sock)
            print(f'Exception at rsa_request(): {e}')
            return

        response = Response()
        response.code = response_code['RSA_KEY_RECEIVED']
        response.payload = request.client_id + cipher_key
        response.payload_size = len(response.payload)

        # send response
        send_all_packets(sock, response)
    else:
        generic_error(sock)
        print("Internal error: Can't decrypt the AES key")


# handle registration request from client,
# if the client name already exist send to client REGISTRATION_FAILED,
# else send to client REGISTRATION_SUCCESS and update the memory,
# no need to update database without the keys - wait for the next request RSA
def registration_request(request, sock, last_seen):
    global clients_table
    request.payload = request.payload

    # check if the client is registered
    ref = False
    with clients_lock:
        for client in clients_table:
            if client[1] == request.payload:
                ref = True

    response = Response()
    if ref:
        response.code = response_code['REGISTRATION_FAILED']
        sock.send_to_client(response.pack())
    else:
        # send response to client
        uid = uuid.uuid4().hex
        # make sure the client id will not include '\n' == '0a'
        # it can become a problem while writing or reading
        # from me.info on the client side
        while '0a' in uid:
            uid = uuid.uuid4().hex
        # save the row with NULLs to continue to the next request - RSA
        # update row in memory
        # row = (client id, client name, 'NULL', last_seen, 'NULL')
        # in a real life project this comment will not be written
        with clients_lock:
            clients_table.append((bytes.fromhex(uid), request.payload, 'NULL', last_seen, 'NULL'))

        response.code = response_code['REGISTRATION_SUCCESS']
        response.payload_size = CLIENT_ID_LEN
        response.payload = bytes.fromhex(uid)

        # send response
        send_all_packets(sock, response)


# entry point
def main():
    # start the server with the port and the two tables
    port = read_info()
    while True:
        # new instance for every thread
        sock = SocketHandler(port)
        print('Waiting for client...')
        sock.wait_for_client_socket()
        print('Connection establish')
        # release worker thread
        threading.Thread(target=get_all_packets, args=(sock,)).start()


if __name__ == '__main__':
    main()
