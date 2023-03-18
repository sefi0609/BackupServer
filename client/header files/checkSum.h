// This code was coped from 
// https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--creating-an-md-5-hash-from-file-content?redirectedfrom=MSDN
// with a some adjustments 

#pragma once
#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>
#include <string>

#define BUFSIZE 1024
#define MD5LEN  16

class CheckSum {
public:
	DWORD cksum(std::string filePath, char* checkSum);
};