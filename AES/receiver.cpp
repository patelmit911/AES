// AES.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "gf.h"
#include "aes.h"
#include <iostream>
#include <vector>
#include <iomanip>
#include <fstream>
#include <iterator>

using namespace std;

vector<vector<uint8_t>> create2Darray(int row, int col);
void printWord(vector<uint8_t> word);
void writeToFile(string fileName, uint8_t* data, int len);
vector<uint8_t> readFile(string fileName);

int main()
{
	vector<uint8_t> bytes = readFile("encrypt.txt");
	int inputLength = bytes.size();
	for (int i = 0; i < inputLength; i++) {
		cout << setfill('0') << setw(2) << hex << static_cast<int>(bytes[i]) << " ";
	}
	cout << endl;

	AES aes(128);
	uint8_t in[16];
	for (int i = 0; i < 16; i++) {
		in[i] = bytes[i];
	}
	//32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
	//uint8_t input[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	//2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
	uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	uint8_t out[16];
	aes.decrypt(in, out, key);
	for (int i = 0; i < 16; i++) {
		cout << setfill('0') << setw(2) << hex << static_cast<int>(out[i]) << " ";
	}
	cout << endl;
	/*uint8_t plain[16];*/
	/*aes.decrypt(in, out, key);
	for (int i = 0; i < 16; i++) {
		cout << setfill('0') << setw(2) << hex << static_cast<int>(out[i]) << " ";
	}
	cout << endl;*/
	writeToFile("plain.txt", out, sizeof(out));

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

void writeToFile(string fileName, uint8_t * data, int len)
{
	ofstream fout;
	fout.open(fileName, ios::binary | ios::out);
	fout.write((char *)data, len);
	fout.close();
}

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

vector<vector<uint8_t>> create2Darray(int row, int col)
{
	vector<vector<uint8_t>> array(row);
	for (int r = 0; r < row; r++) {
		vector<uint8_t> a(col);
		for (int c = 0; c < col; c++) {
			a[c] = 0x00;
		}
		array[r] = a;
	}
	return array;
}


