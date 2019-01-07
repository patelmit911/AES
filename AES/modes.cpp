#include "pch.h"
#include "modes.h"
#include "aes.h"
#include <random>

modes::modes()
{
}

/*
 *	MSC52-CPP.	
 *		Value-returning functions must return a value from all exit paths
 *	CTR50-CPP. 	
 *		Guarantee that container indices and iterators are within the valid range.
 *		All the vectors are accessed after finding their range.
 *	CTR52-CPP. 
 *		Guarantee that library functions do not overflow
 *	CTR53-CPP.
 *		Use valid iterator ranges
 */
std::vector<uint8_t> modes::ecbEncrypt(std::vector<uint8_t> message, std::vector<uint8_t> key)
{
	int len = key.size() * 8;
	if (!isValidKey(len)) {
		std::cout << "ERROR" << std::endl;
		return message;
	}
	AES aes(key);
	std::vector<std::vector<uint8_t>> blocks = pad(message);
	std::vector<uint8_t> cipher;
	int totalBlocks = blocks.size();
	for (int i = 0; i < totalBlocks; i++) {
		
		std::vector<uint8_t> block = blocks[i];
		
		
		std::vector<uint8_t> out = aes.encrypt(block);
		
		for (int j = 0; j < 16; j++) {
			cipher.push_back(out[j]);
		}
		
	}
	return cipher;
}

/*
 *	MSC52-CPP.
 *		Value-returning functions must return a value from all exit paths
 */
std::vector<uint8_t> modes::ecbDecrypt(std::vector<uint8_t> cipher, std::vector<uint8_t> key)
{
	int len = key.size() * 8;
	if (!isValidKey(len)) {
		std::cout << "ERROR" << std::endl;
		return cipher;
	}
	AES aes(key);
	int totalBlocks = cipher.size() / 16;
	std::vector<std::vector<uint8_t>> blocks;
	for (int i = 0; i < totalBlocks; i++) {
		std::vector<uint8_t> block(16);
		for (int j = 0; j < 16; j++) {
			block[j] = cipher[(i * 16) + j];
		}
		blocks.push_back(block);
	}
	std::vector<std::vector<uint8_t>> plainTextBlocks;
	for (int i = 0; i < totalBlocks; i++) {
		uint8_t in[16];
		std::vector<uint8_t> block = blocks[i];
		for (int j = 0; j < 16; j++) {
			in[j] = block[j];
		}
		std::vector<uint8_t> out = aes.decrypt(block);
		std::vector<uint8_t> plainBlock(16);
		for (int j = 0; j < 16; j++) {
			plainBlock[j] = out[j];
		}
		plainTextBlocks.push_back(plainBlock);
	}
	std::vector<uint8_t> plainText = removePads(plainTextBlocks);
	return plainText;
}

/*
 *	MSC52-CPP.
 *		Value-returning functions must return a value from all exit paths
 */
std::vector<uint8_t> modes::cbcEncrypt(std::vector<uint8_t> message, std::vector<uint8_t> key)
{
	int len = key.size() * 8;
	if (!isValidKey(len)) {
		std::cout << "ERROR" << std::endl;
		return message;
	}
	AES aes(key);
	std::vector<std::vector<uint8_t>> blocks = pad(message);
	std::vector<std::vector<uint8_t>> cipherBlocks;
	std::vector<uint8_t> IV = generateRandomBlock();
	cipherBlocks.push_back(IV);
	int totalBlocks = blocks.size();
	for (int i = 0; i < totalBlocks; i++) {
		std::vector<uint8_t> block = blocks[i];				
		std::vector<uint8_t> out = aes.encrypt(blockXOR(block, cipherBlocks[i]));
		cipherBlocks.push_back(out);
	}
	std::vector<uint8_t> cipher;
	for (int i = 0; i < totalBlocks+1; i++) {
		std::vector<uint8_t> block = cipherBlocks[i];
		for (int j = 0; j < 16; j++) {
			cipher.push_back(block[j]);
		}
	}
	return cipher;
}

/*
 *	MSC52-CPP.
 *		Value-returning functions must return a value from all exit paths
 */
std::vector<uint8_t> modes::cbcDecrypt(std::vector<uint8_t> cipher, std::vector<uint8_t> key)
{
	int len = key.size() * 8;
	if (!isValidKey(len)) {
		std::cout << "ERROR" << std::endl;
		return cipher;
	}
	AES aes(key);
	int totalBlocks = cipher.size() / 16;
	std::vector<std::vector<uint8_t>> blocks;
	for (int i = 0; i < totalBlocks; i++) {
		std::vector<uint8_t> block(16);
		for (int j = 0; j < 16; j++) {
			block[j] = cipher[(i * 16) + j];
		}
		blocks.push_back(block);
	}
	std::vector<uint8_t> IV = blocks[0];
	std::vector<std::vector<uint8_t>> plainTextBlocks;
	for (int i = 1; i < totalBlocks; i++) {
		std::vector<uint8_t> block = blocks[i];
		std::vector<uint8_t> out = blockXOR(aes.decrypt(block), blocks[i-1]);
		plainTextBlocks.push_back(out);
	}
	std::vector<uint8_t> plainText = removePads(plainTextBlocks);
	return plainText;
}

modes::~modes()
{
}

std::vector<std::vector<uint8_t>> modes::pad(std::vector<uint8_t> message)
{
	int len = message.size();
	int fullBlocks = len / 16;
	std::vector<std::vector<uint8_t>> blocks;
	for (int i = 0; i < fullBlocks; i++) {
		std::vector<uint8_t> block(16);
		for (int j = 0; j < 16; j++) {
			block[j] = message[(i * 16) + j];
		}
		blocks.push_back(block);
	}
	int remainingBytes = 16 - (len - (fullBlocks * 16));
	std::vector<uint8_t> block;
	for (int i = (fullBlocks * 16); i < len; i++) {
		block.push_back(message[i]);
	}
	remainingBytes = remainingBytes == 0 ? 16 : remainingBytes;
	for (int i = 0; i < remainingBytes; i++) {
		block.push_back(remainingBytes);
	}
	blocks.push_back(block);
	return blocks;
}

std::vector<uint8_t> modes::removePads(std::vector<std::vector<uint8_t>> blocks)
{
	int noOfBlocks = blocks.size();
	std::vector<uint8_t> message;
	for (int i = 0; i < noOfBlocks - 1; i++) {
		std::vector<uint8_t> block = blocks[i];
		for (int j = 0; j < 16; j++) {
			message.push_back(block[j]);
		}
	}
	std::vector<uint8_t> block = blocks[noOfBlocks - 1];
	int len = 16 - block[15];
	for (int i = 0; i < len; i++) {
		message.push_back(block[i]);
	}
	return message;
}

std::vector<uint8_t> modes::blockXOR(std::vector<uint8_t> a, std::vector<uint8_t> b)
{
	std::vector<uint8_t> ans(16);
	for (int i = 0; i < 16; i++) {
		ans[i] = a[i] ^ b[i];
	}
	return ans;
}

/*
 *	RULE MSC50-CPP
 *		Do not use std::rand() for generating pseudorandom numbers
 *	RULE MSC51-CPP
 *		Ensure your random number generator is properly seeded
 */
std::vector<uint8_t> modes::generateRandomBlock()
{
	std::vector<uint8_t> randomBlock(16);
	std::uniform_int_distribution<int> distribution(0, 255);
	std::random_device rd;
	std::mt19937 engine(rd());
	for (int i = 0; i < 16; i++) {
		randomBlock[i] = distribution(engine);
	}
	return randomBlock;
}

bool modes::isValidKey(int length)
{
	if (length == 128 || length == 192 || length == 256)	return true;
	return false;
}
