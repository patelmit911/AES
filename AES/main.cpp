/*	RULE MSC52-CPP. 
 *		Value-returning functions must return a value from all exit paths
 *	CTR50-CPP. Guarantee that container indices and iterators are within the valid range
 *	CTR52-CPP. Guarantee that library functions do not overflow
 *	CTR53-CPP. Use valid iterator ranges
 *	CTR55-CPP. Do not use an additive operator on an iterator if the result would overflow
 *	MSC50-CPP. Do not use std::rand() for generating pseudorandom numbers
 *	MSC51-CPP. Ensure your random number generator is properly seeded
 *	MSC52-CPP. Value-returning functions must return a value from all exit paths
 *	OOP58-CPP. Copy operations must not mutate the source object
 *	DCL51-CPP. Do not declare or define a reserved identifier
 *	DCL55-CPP. Avoid information leakage when passing a class object across a trust boundary
 *	DCL60-CPP. Obey the one-definition rule
 *  CRYPTO CODING PRACTICE
 *		Use unsigned bytes to represent binary data
 */

#include "pch.h"
#include "aes.h"
#include "modes.h"
#include <iostream>
#include <vector>
#include <iomanip>
#include <fstream>
#include <iterator>
#include <random>

using namespace std;

vector<uint8_t> readFile(string fileName);
void writeVecToFile(string fileName, vector<uint8_t> data);

int main()
{
	int keyLength = 128;
	int bytes = keyLength / 8;
	modes mode;

	// Initialize the key
	uint8_t key_arr[32] = { 0x2c, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
							0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 
							0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
							0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	std::vector<uint8_t> key;

	//	OOP58-CPP. Copy operations must not mutate the source object
	for (int i = 0; i < bytes; i++) {
		key.push_back(key_arr[i]);
	}

	// Encryption
	vector<uint8_t> data = readFile("Capture.png");
	vector<uint8_t> cipherText = mode.cbcEncrypt(data, key);
	writeVecToFile("sec.png", cipherText);			// Storing the resultant cipher text

	// Decryption
	vector<uint8_t> cipher = readFile("sec.png");	// Read 
	vector<uint8_t> plainText = mode.cbcDecrypt(cipher, key);
	writeVecToFile("real.png", plainText);	

	return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file

void printWord(vector<uint8_t> word) {
	for (int i = 0; i < 4; i++) {
		cout << setfill('0') << setw(2) << hex << static_cast<int>(word[i]);
		cout << " ";
	}
	cout << endl;
}

/*	RULE : FIO51-CPP
 *	Failing to properly close files may allow an attacker to exhaust system resources and can increase
 *	the risk that data written into in-memory file buffers will not be flushed in the event of abnormal
 *	program termination.
 */
void writeToFile(string fileName, uint8_t * data, int len)
{
	ofstream fout;
	fout.open(fileName, ios::binary | ios::out);
	fout.write((char *)data, len);
	fout.close();
}
/*	RULE : FIO51-CPP
 *	Failing to properly close files may allow an attacker to exhaust system resources and can increase
 *	the risk that data written into in-memory file buffers will not be flushed in the event of abnormal
 *	program termination.
 */
void writeVecToFile(string fileName, vector<uint8_t> data)
{
	ofstream fout;
	fout.open(fileName, ios::binary | ios::out);
	fout.write(reinterpret_cast<const char*>(&data[0]), data.size() * sizeof(uint8_t));
	fout.close();
}
/*	RULE : FIO51-CPP
 *	Failing to properly close files may allow an attacker to exhaust system resources and can increase
 *	the risk that data written into in-memory file buffers will not be flushed in the event of abnormal
 *	program termination.
 */
vector<uint8_t> readFile(string fileName)
{
	vector<uint8_t> bytes;
	ifstream file1(fileName, ios_base::in | ios_base::binary);
	uint8_t ch = file1.get();
	while (file1.good())
	{
		bytes.push_back(ch);
		ch = file1.get();
	}
	return bytes;
}
