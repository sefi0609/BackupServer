import os


def write_file(client_name, file_name, file_content):
    """
    write binary a new file received from client to the proper path,
    if the path doesn't exist - create this path
    """
    if not os.path.isdir(f'files/{client_name}'):
        os.makedirs(f'files/{client_name}')
    with open(f'files/{client_name}/{file_name}', 'ab') as file:
        file.write(file_content)


def read_info():
    """
    read from the port.info file to get the servers port
    if there is no file or the file is empty set default port
    """
    try:
        with open('port.info') as file:
            port = int(file.read())
    except Exception as e:
        print(e)
        print('Setting default port: 1234')
        port = 1234
    return port
