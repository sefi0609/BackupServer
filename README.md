# Project Overview
Hello and welcome to my BackupServer project.  
This is a Multi-threaded client server application.  
In this project I have worked with: Crypto libraries, DataBase - Sqlite3, Sockets, Files, Binary Files  
and checkSum calculation as per Linux with a littel twist.  
If the client is not registered to the service, then he will first register,  
Then he will generate an RSA key pair and send the public key to the server.  
The server generates a symmetric key, encrypt it with the RSA public key from the client  
and sends the encrypted key to the client.  
The client decrypt the encrypted key. at this point both the client and the server have the same symmetric key.  
Now the client encrypt the file content and send it to the server.  
The server decrypt the file content and write the file to a specific directory for the client.  
If it is the first file that belongs to the client the server will create a new directory for the clients files.  
To verify that the file received by the server properly, the server will calculate checkSum value as per Linux  
and will send it to the client to verify it.  
The client will also calculate the checkSum and compare the two values.  
If the values are not equal the client will try to send the file again, 3 times total.  
To pack the checkSum value into 4 bytes I have calculated the sum of this value by 8 chunks.  
The checkSum is used for Cyclic redundancy check as was explained above.  
If the client is already registered he will request to reconnect to the server to send another file.  
For every session the server will generate a new key, The rest is as described above.   

# images

> registration and reconnect 
### client 
![client_full_flow](https://user-images.githubusercontent.com/81361291/225738731-ecf6025c-4ea3-4428-8c41-6d4aab872341.PNG)
### server
![server_full_flow](https://user-images.githubusercontent.com/81361291/225738025-daef159a-1eab-4927-bd17-0b041b1bef58.PNG)

> file is already on the server 
### client
![error_full_flow_clinet](https://user-images.githubusercontent.com/81361291/225739226-58af1087-db42-4084-9306-e114da84f601.PNG)
