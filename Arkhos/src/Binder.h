#pragma once
#ifndef __BINDER_H__
#define __BINDER_H__

#include <string>
#include <vector>
#include <Windows.h>

// x = address, y = alignment
#define ALIGN(x, y) ((((x + y) - 1) / y) * y)

#define SHELLCODE_START_OFFSET 0x63E
#define SHELLCODE_OEP_OFFSET 0x4C

class Binder {
	private:
	std::vector<BYTE> shellcode;
	static Binder *instance;
	std::wstring targetFileName;
	std::wstring payloadFileName;
	std::wstring outputFileName;

	Binder();
	~Binder() {};
	Binder(Binder& b) {};
	Binder& operator=(Binder& b) {};

	public:
	static Binder *GetInstance();
	void SetTargetFile(std::wstring target);
	void SetPayloadFile(std::wstring payload);
	void SetOutputFile(std::wstring output);
	bool Bind();
};

#endif // !__BINDER_H__
