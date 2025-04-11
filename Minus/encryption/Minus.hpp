#pragma once
#include <string>
#include <vector>
#include <random>
#include <array>
#include <iomanip>
#include <sstream>
#include <windows.h>
#include <TlHelp32.h>

#define CRYPT_START auto _runtime_key = Minus_class::GenerateRuntimeKey();
#define CRYPT_END Minus_class::ClearRuntimeKey(_runtime_key);

namespace
{
	constexpr uint8_t KEY_DATA[] =
	{
		0x4A, 0x7B, 0x1C, 0x8D, 0xF1, 0xE2, 0xD3, 0xC4,
		0xDE, 0xAD, 0xBE, 0xEF, 0x89, 0xAB, 0xCD, 0xEF
	};

	template<size_t N>
	struct EncryptedString
	{
		char data[N];
		constexpr EncryptedString(const char(&str)[N])
		{
			for (size_t i = 0; i < N; i++)
			{
				char c = str[i];
				c ^= KEY_DATA[i % sizeof(KEY_DATA)];
				c ^= static_cast<char>((i * 7) & 0xFF);
				c ^= static_cast<char>((N * 13) & 0xFF);
				data[i] = c;
			}
		}
	};
}

#define SECURE_STR(str) []() { \
	constexpr auto encrypted = EncryptedString<sizeof(str)>(str); \
	static char decrypted[sizeof(str)]; \
	for (size_t i = 0; i < sizeof(str); i++) { \
		char c = encrypted.data[i]; \
		c ^= static_cast<char>((sizeof(str) * 13) & 0xFF); \
		c ^= static_cast<char>((i * 7) & 0xFF); \
		c ^= KEY_DATA[i % sizeof(KEY_DATA)]; \
		decrypted[i] = c; \
	} \
	return decrypted; \
}()

#define SECURE_WSTR(str) []() { \
	static auto decrypted = SECURE_STR(str); \
	static std::wstring wide(decrypted, decrypted + strlen(decrypted)); \
	return wide.c_str(); \
}()

class Minus_class
{
private:
	static constexpr uint32_t PRIMARY_KEY = 0x4A7B1C8D;
	static constexpr uint32_t SECONDARY_KEY = 0xF1E2D3C4;
	static constexpr uint32_t INTEGRITY_KEY = 0xDEADBEEF;
	static constexpr size_t KEY_SCHEDULE_SIZE = 256;
	static constexpr uint32_t MAGIC1 = 0x5A827999;
	static constexpr uint32_t MAGIC2 = 0x6ED9EBA1;
	static constexpr uint32_t MAGIC3 = 0x8F1BBCDC;

	HANDLE integrity_check_thread;
	bool should_monitor;
	bool (*original_function_ptr)();

	struct ProcessInfo {
		DWORD pid;
		std::string name;
		std::string path;
	};
	std::vector<ProcessInfo> suspicious_processes;
	std::vector<std::string> blacklisted_windows;

	std::vector<uint8_t> runtime_key;
	std::random_device rd;
	std::mt19937 gen;

public:
	HANDLE GetIntegrityCheckThread() const
	{
		return integrity_check_thread;
	}

	template<size_t N>
	static const char* SecureString(const char* input)
	{
		static char encrypted[N];
		static char decrypted[N];
		static bool initialized = false;

		if (!initialized)
		{
			for (size_t i = 0; i < N; i++)
			{
				uint8_t b = input[i];
				b ^= KEY_DATA[i % sizeof(KEY_DATA)];
				b = RotateLeft(b, 3) ^ RotateRight(b, 5);
				b ^= static_cast<uint8_t>(MAGIC1 >> ((i % 4) * 8));
				b += static_cast<uint8_t>(i * MAGIC2);
				b ^= static_cast<uint8_t>(MAGIC3 >> ((i % 4) * 8));
				encrypted[i] = b;
			}
			initialized = true;
		}

		for (size_t i = 0; i < N; i++)
		{
			uint8_t b = encrypted[i];
			b ^= static_cast<uint8_t>(MAGIC3 >> ((i % 4) * 8));
			b -= static_cast<uint8_t>(i * MAGIC2);
			b ^= static_cast<uint8_t>(MAGIC1 >> ((i % 4) * 8));
			b = RotateRight(b, 3) ^ RotateLeft(b, 5);
			b ^= KEY_DATA[i % sizeof(KEY_DATA)];
			decrypted[i] = b;
		}

		return decrypted;
	}

	template<size_t N>
	static const wchar_t* SecureWString(const char* input)
	{
		static const char* decrypted = SecureString<N>(input);
		static std::wstring wide(decrypted, decrypted + strlen(decrypted));
		return wide.c_str();
	}

	static std::vector<uint8_t> GenerateRuntimeKey();
	static void ClearRuntimeKey(std::vector<uint8_t>& key);

	bool Initialize();
	void ObfuscateStrings();
private:
	uint32_t CalculateChecksum(const std::vector<uint8_t>& data);

	static constexpr uint8_t RotateLeft(uint8_t value, unsigned int count)
	{
		return static_cast<uint8_t>((value << count) | (value >> (8 - count)));
	}

	static constexpr uint8_t RotateRight(uint8_t value, unsigned int count)
	{
		return static_cast<uint8_t>((value >> count) | (value << (8 - count)));
	}

	friend DWORD WINAPI IntegrityCheckThread(LPVOID param);
};

static Minus_class Minus;