#include "Minus.hpp"
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <algorithm>
#include <TlHelp32.h>
#include <Psapi.h>
#include <DbgHelp.h>
#include <iostream>
#include <thread>
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "DbgHelp.lib")

namespace
{
    constexpr uint32_t PRIMARY_KEY = 0x4A7B1C8D;
    constexpr uint32_t SECONDARY_KEY = 0xF1E2D3C4;
    constexpr uint32_t INTEGRITY_KEY = 0xDEADBEEF;
    constexpr size_t KEY_SCHEDULE_SIZE = 256;
}

uint32_t Minus_class::CalculateChecksum(const std::vector<uint8_t>& data)
{
    uint32_t checksum = INTEGRITY_KEY;
    for (uint8_t byte : data)
    {
        checksum ^= byte;
        checksum = (checksum << 7) | (checksum >> 25);
    }
    return checksum;
}

std::vector<uint8_t> Minus_class::GenerateRuntimeKey()
{
    std::vector<uint8_t> key(KEY_SCHEDULE_SIZE);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < key.size(); i++) {
        key[i] = static_cast<uint8_t>(dis(gen));
    }
    return key;
}

void Minus_class::ClearRuntimeKey(std::vector<uint8_t>& key)
{
    std::fill(key.begin(), key.end(), 0);
}

bool Minus_class::Initialize()
{
    gen.seed(rd());
    runtime_key = GenerateRuntimeKey();
}

void Minus_class::ObfuscateStrings()
{

}