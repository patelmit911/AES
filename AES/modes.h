#pragma once

#include "aes.h"
#include <iostream>
#include <vector>
#include <iomanip>

class modes
{
public:
	modes();
	std::vector<uint8_t> ecbEncrypt(std::vector<uint8_t> message, std::vector<uint8_t> key);
	std::vector<uint8_t> ecbDecrypt(std::vector<uint8_t> cipher, std::vector<uint8_t> key);
	std::vector<uint8_t> cbcEncrypt(std::vector<uint8_t> message, std::vector<uint8_t> key);
	std::vector<uint8_t> cbcDecrypt(std::vector<uint8_t> cipher, std::vector<uint8_t> key);
	~modes();
private:
	int keyLength = 128;
	std::vector<std::vector<uint8_t>> pad(std::vector<uint8_t> message);
	std::vector<uint8_t> removePads(std::vector<std::vector<uint8_t>> blocks);
	std::vector<uint8_t> blockXOR(std::vector<uint8_t> a, std::vector<uint8_t> b);
	std::vector<uint8_t> generateRandomBlock();
	bool isValidKey(int length);
};

