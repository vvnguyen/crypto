#pragma once
#include <iostream>
#include <vector>
#include <random>
//Text encryption based on pseudorandom numbers generator
//https://pdfs.semanticscholar.org/6f1e/616cfa562826eee6188dc9caffbe4bcf8d66.pdf
//Used Visual Studio 2017 to compile
//https://msdn.microsoft.com/en-us/library/bb982250.aspx states random_device generated numbers
//in visual studio are non-deterministic and cryptographically secure
using namespace std;

namespace waterdown {
	//Encryption is process of converting data to unrecognizable form
	typedef unsigned int symbol;
	const size_t maximum_text_length = 16;
	const size_t password_length = 64; //this is in quadruplets of chars that is 64 for example means 4*64 = 256 char long password

	symbol random_symbol() {
		static std::random_device rd;
		return <symbol>rd();
	}

	bool encrypt(vector<symbol>& plain_text, vector<symbol>& encrypted_text, int key[password_length + 1]) {
		if (plain_text.size() > maximum_text_length) {
			return false;
		}

		const size_t extended_size = 16 * 1024;
		const size_t part_size = extended_size / password_length;
		const size_t text_length = plain_text.size();

		vector<symbol> mask(text_length);
		for (int i = 0;i < text_length;++i) {
			mask[i] = random_symbol();
		}

		try {
			encrypted_text.resize(extended_size);
		}
		catch (std::bad_alloc& wrong_alloc) {
			std::cerr << "bad_alloc caught: " << wrong_alloc.what() << '\n';
			return false;
		}
		if (encrypted_text.size() != extended_size) {
			return false;
		}

		encrypted_text.resize(0);
		encrypted_text.reserve(extended_size);
		encrypted_text = plain_text;
		for (int i = 0;i < encrypted_text.size();++i) {
			encrypted_text[i] += mask[i];
		}
		int up = 0;

		for (int key_part_index = 0;key_part_index < password_length;++key_part_index) {
			mt19937 mt_rand(key[key_part_index]);
			for (int i = 0;i < part_size; ++i) {
				std::uniform_int_distribution<int> dis(0, up + text_length);
				int insert_index = dis(mt_rand);

				char rchar = random_symbol();
				try {
					encrypted_text.insert(encrypted_text.begin() + insert_index, rchar);
				}
				catch (std::bad_alloc& wrong_alloc) {
					std::cerr << "bad_alloc caught: " << wrong_alloc.what() << '\n';
					return false;
				}
				++up;
			}
		}

		mt19937 mt_rand(key[password_length]);
		for (int ins = 0;ins < text_length;++ins) {
			std::uniform_int_distribution<int> dis(0, up + text_length);
			int insert_index = dis(mt_rand);
			encrypted_text.insert(encrypted_text.begin() + insert_index, mask[ins]);
			++up;
		}

		return true;
	}

	bool decrypt(vector<symbol>& encrypted_text, int key[password_length + 1]) {
		const size_t extended_size = 16 * 1024;
		const size_t part_size = extended_size / password_length;
		vector<int> index;
		size_t text_length = encrypted_text.size();
		text_length -= extended_size;
		text_length /= 2;
		try {
			index.resize(part_size);
		}
		catch (std::bad_alloc& wrong_alloc) {
			std::cerr << "bad_alloc caught: " << wrong_alloc.what() << '\n';
			return false;
		}
		int up = 0;
		vector<int> indexes_elements_to_be_removed;
		vector<symbol> mask(text_length);
		for (int key_part_index = 0; key_part_index < password_length; ++key_part_index) {
			mt19937 mt_rand(key[key_part_index]);

			for (int i = 0;i < part_size; ++i) {
				std::uniform_int_distribution<int> dis(0, up + text_length);
				int insert_index = dis(mt_rand);
				indexes_elements_to_be_removed.push_back(insert_index);
				++up;
			}
		}

		mt19937 mt_rand(key[password_length]);

		vector<int>mask_location(text_length);
		for (int ins = 0;ins < text_length;++ins) {
			std::uniform_int_distribution<int> dis(0, up + text_length);
			int insert_index = dis(mt_rand);
			mask_location[ins] = insert_index;
			++up;
		}
		for (int rem = (text_length - 1);rem >= 0;--rem) {
			mask[rem] = encrypted_text[mask_location[rem]];
			encrypted_text.erase(encrypted_text.begin() + mask_location[rem]);
		}
		for (int i = indexes_elements_to_be_removed.size() - 1;i >= 0;--i) {
			if (indexes_elements_to_be_removed[i] > encrypted_text.size()) {
				cout << "Error : " << encrypted_text.size() << " " << indexes_elements_to_be_removed[i] << " " << i;
				return false;
			}
			encrypted_text.erase(encrypted_text.begin() + indexes_elements_to_be_removed[i]);
		}

		for (int k = 0;k < text_length;++k) {
			encrypted_text[k] -= mask[k];
		}
		return true;
	}

}
