#include "pch.h"
#include "AES.h"
#include <iostream>
#include <iomanip>
#include <stdint.h>
#include <vector>


/*
 *	OOP53-CPP. Write constructor member initializers in the canonical order
 */
AES::AES(std::vector<uint8_t> key)
{
	int len = key.size() * 8;
	switch (len)
	{
	case 128:
		Nk = 4;
		Nb = 4;
		Nr = 10;
		break;
	case 192:
		Nk = 6;
		Nb = 4;
		Nr = 12;
		break;
	case 256:
		Nk = 8;
		Nb = 4;
		Nr = 14;
		break;
	default:
		std::cout << "error";
		break;
	}
	rcon.push_back(createWord(0x00, 0x00, 0x00, 0x00));
	rcon.push_back(createWord(0x01, 0x00, 0x00, 0x00));
	uint8_t x = 0x01;
	for (int i = 2; i < Nb*(Nr + 1); i++) {
		x = multiply(x, 0x02);
		rcon.push_back(createWord(x, 0x00, 0x00, 0x00));
	}
	expandedKey = keyExpansion(key);
}

void AES::print(uint8_t state[][4])
{
	for (int i = 0; i < 4; i++) {		
		for (int j = 0; j < 4; j++) {
			std::cout << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(state[i][j]) << " ";
		}
		std::cout << std::endl;
	}
}

/*
 *	RULE OOP58-CPP. 
 *		Copy operations must not mutate the source object.
 *	CTR52-CPP. 
 *		Guarantee that library functions do not overflow.
 */
std::vector<uint8_t> AES::encrypt(std::vector<uint8_t> in)
{
	std::vector<uint8_t> out(16);
	uint8_t state[4][4];
	for (int r = 0; r < 4; r++) {
		for (int c = 0; c < 4; c++) {
			state[r][c] = in[r + 4 * c];
		}
	}

	addRoundKey(state, 0, expandedKey);
	for (int round = 1; round < Nr; round++) {
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, round, expandedKey);
	}
	subBytes(state);
	shiftRows(state);
	addRoundKey(state, Nr, expandedKey);

	for (int r = 0; r < 4; r++) {
		for (int c = 0; c < 4; c++) {
			out[r + 4 * c] = state[r][c];
		}
	}
	
	return out;
}

/*
 *	OOP58-CPP.
 *		Copy operations must not mutate the source object.
 *	CTR52-CPP.
 *		Guarantee that library functions do not overflow.
 */
std::vector<uint8_t> AES::decrypt(std::vector<uint8_t> in)
{
	std::vector<uint8_t> out(16);
	uint8_t state[4][4];
	for (int r = 0; r < 4; r++) {
		for (int c = 0; c < 4; c++) {
			state[r][c] = in[r + 4 * c];
		}
	}

	addRoundKey(state, Nr, expandedKey);
	for (int round = (Nr - 1); round >= 1; round--) {
		invShiftRows(state);
		invSubBytes(state);
		addRoundKey(state, round, expandedKey);
		invMixColumns(state);
	}
	invShiftRows(state);
	invSubBytes(state);
	addRoundKey(state, 0, expandedKey);

	for (int r = 0; r < 4; r++) {
		for (int c = 0; c < 4; c++) {
			out[r + 4 * c] = state[r][c];
		}
	}
	return out;
}

AES::~AES()
{
}

/*
 *	CTR52-CPP.
 *		Guarantee that library functions do not overflow.
 */
std::vector<std::vector<uint8_t>> AES::keyExpansion(std::vector<uint8_t> key)
{
	std::vector<uint8_t> temp(4);
	std::vector<std::vector<uint8_t>> w = create2Darray(Nb * (Nr + 1), 4);
	for (int i = 0; i < Nk; i++) {
		w[i] = createWord(key[4 * i + 0], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
	}
	for (int i = Nk; i < Nb*(Nr + 1); i++) {
		temp = w[i - 1];
		if (i % Nk == 0) {
			temp = wordXOR(subWord(rotWord(temp)), rcon[i / Nk]);
		}
		else if ((Nk > 6) && (i % Nk == 4)) {
			temp = subWord(temp);
		}
		w[i] = wordXOR(w[i - Nk], temp);
	}

	return w;
}

std::vector<uint8_t> AES::rotWord(std::vector<uint8_t> a)
{
	std::vector<uint8_t> word(4);
	for (int i = 0; i < 4; i++) {
		word[i] = a[(i + 1) % 4];
	}
	return word;
}

std::vector<uint8_t> AES::RCON(int i)
{
	std::vector<uint8_t> word(4);
	word[0] = (0x01) << (i - 1);
	word[1] = 0x00;
	word[2] = 0x00;
	word[3] = 0x00;
	return word;
}

void AES::addRoundKey(uint8_t state[][4], int round, std::vector<std::vector<uint8_t>> key)
{
	int l = round * Nb;
	for (int c = 0; c < 4; c++) {
		std::vector<uint8_t> word = key[l + c];
		for (int r = 0; r < 4; r++) {
			state[r][c] = state[r][c] ^ word[r];
		}
	}
}

void AES::subBytes(uint8_t state[][4])
{
	for (int r = 0; r < 4; r++) {
		for (int c = 0; c < 4; c++) {
			int col = static_cast<int>((state[r][c] & 0x0f));
			int row = static_cast<int>((state[r][c] & 0xf0) >> 4);
			state[r][c] = S_BOX[row][col];
		}
	}
}

void AES::shiftRows(uint8_t state[][4])
{
	for (int r = 1; r < 4; r++) {
		uint8_t shift[4];
		for (int c = 0; c < 4; c++) {
			shift[c] = state[r][(c + r) % Nb];
		}
		for (int c = 0; c < 4; c++) {
			state[r][c] = shift[c];
		}
	}
}

void AES::mixColumns(uint8_t state[][4])
{
	for (int c = 0; c < Nb; c++) {
		uint8_t s[4];
		s[0] = (multiply(state[0][c], 0x02)) ^ (multiply(state[1][c], 0x03)) ^ (state[2][c]) ^ (state[3][c]);
		s[1] = (state[0][c]) ^ (multiply(state[1][c], 0x02)) ^ (multiply(state[2][c], 0x03)) ^ (state[3][c]);
		s[2] = (state[0][c]) ^ (state[1][c]) ^ (multiply(state[2][c], 0x02)) ^ (multiply(state[3][c], 0x03));
		s[3] = (multiply(state[0][c], 0x03)) ^ (state[1][c]) ^ (state[2][c]) ^ (multiply(state[3][c], 0x02));
		for (int r = 0; r < 4; r++) {
			state[r][c] = s[r];
		}
	}
}

void AES::invSubBytes(uint8_t state[][4])
{
	for (int r = 0; r < 4; r++) {
		for (int c = 0; c < 4; c++) {
			int col = static_cast<int>((state[r][c] & 0x0f));
			int row = static_cast<int>((state[r][c] & 0xf0) >> 4);
			state[r][c] = INV_S_BOX[row][col];
		}
	}
}

void AES::invShiftRows(uint8_t state[][4])
{
	for (int r = 1; r < 4; r++) {
		uint8_t shift[4];
		for (int c = 0; c < 4; c++) {
			shift[c] = state[r][(c + (Nb-r)) % Nb];
		}
		for (int c = 0; c < 4; c++) {
			state[r][c] = shift[c];
		}
	}
}

void AES::invMixColumns(uint8_t state[][4])
{
	for (int c = 0; c < Nb; c++) {
		uint8_t s[4];
		s[0] = (multiply(state[0][c], 0x0e)) ^ (multiply(state[1][c], 0x0b)) ^ (multiply(state[2][c], 0x0d)) ^ (multiply(state[3][c], 0x09));
		s[1] = (multiply(state[0][c], 0x09)) ^ (multiply(state[1][c], 0x0e)) ^ (multiply(state[2][c], 0x0b)) ^ (multiply(state[3][c], 0x0d));
		s[2] = (multiply(state[0][c], 0x0d)) ^ (multiply(state[1][c], 0x09)) ^ (multiply(state[2][c], 0x0e)) ^ (multiply(state[3][c], 0x0b));
		s[3] = (multiply(state[0][c], 0x0b)) ^ (multiply(state[1][c], 0x0d)) ^ (multiply(state[2][c], 0x09)) ^ (multiply(state[3][c], 0x0e));
		for (int r = 0; r < 4; r++) {
			state[r][c] = s[r];
		}
	}
}

uint8_t AES::multiply(uint8_t a, uint8_t b)
{	
	uint8_t ans = 0x00;
	uint8_t extra = 0x00;
	while (b) {
		if (b & 0x01)	ans = ans ^ a;
		else extra = extra ^ a;
		b = b >> 1;
		if (a & 0x80) {
			a = (a << 1) ^ 0x1b;
		}
		else {
			a = (a << 1) ^ 0x00;
		}
	}
	return ans;	
}

std::vector<std::vector<uint8_t>> AES::create2Darray(int row, int col)
{
	std::vector<std::vector<uint8_t>> array(row);
	for (int r = 0; r < row; r++) {
		std::vector<uint8_t> a(col);
		for (int c = 0; c < col; c++) {
			a[c] = 0x00;
		}
		array[r] = a;
	}
	return array;
}

std::vector<uint8_t> AES::createWord(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
	std::vector<uint8_t> word(4);
	word[0] = a;
	word[1] = b;
	word[2] = c;
	word[3] = d;
	return word;
}

std::vector<uint8_t> AES::wordXOR(std::vector<uint8_t> a, std::vector<uint8_t> b)
{
	std::vector<uint8_t> ans(4);
	for (int i = 0; i < 4; i++) {
		ans[i] = a[i] ^ b[i];
	}
	return ans;
}

std::vector<uint8_t> AES::subWord(std::vector<uint8_t> a)
{
	std::vector<uint8_t> word(4);
	for (int i = 0; i < 4; i++) {
		int col = static_cast<int>((a[i] & 0x0f));
		int row = static_cast<int>((a[i] & 0xf0) >> 4);
		word[i] = S_BOX[row][col];
	}
	return word;
}


