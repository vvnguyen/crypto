#pragma once
#include <windows.h>
#include <chrono>

unsigned int get_entrophy(int n) {
	unsigned int random_int = 0;
	for (int i = 0;i < (n-1);++i) {
		auto begin = std::chrono::high_resolution_clock::now();
		auto time = begin.time_since_epoch();
		unsigned a = time.count();
		if (a & 1) {
			random_int |= (1<<i);
		}
	}
	return random_int;
}