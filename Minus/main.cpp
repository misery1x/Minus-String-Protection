#include "encryption/Minus.hpp"
#include <iostream>
#include <iomanip>
#include <string>

void PrintHex(const std::vector<uint8_t>& data, const std::string& label)
{
    std::cout << label << ": ";

    for (const auto& byte : data)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }

    std::cout << std::dec << std::endl;
}

int main()
{
    if (!Minus.Initialize())
    {
        std::cout << "Failed to initialize Minus!" << std::endl;
        return 1;
    }
    std::cout << "Minus initialized successfully." << std::endl << std::endl;

    std::cout << "Runtime Key Generation:" << std::endl;
    auto runtime_key = Minus_class::GenerateRuntimeKey();
    PrintHex(runtime_key, "Generated Runtime Key");
    
    std::cout << "\nSecure String Demo:" << std::endl;
    const char* original_str = "Hello, Secure World!";
    const char* secure_str = Minus_class::SecureString<20>(original_str);
    std::cout << "Original string: " << original_str << std::endl;
    std::cout << "Secure string: " << secure_str << std::endl;
    
    std::cout << "\nSecure Wide String" << std::endl;
    const wchar_t* secure_wstr = Minus_class::SecureWString<20>(original_str);

    const char* secure_str_literal = SECURE_STR("This is a secure string");
    std::cout << "Secure string from macro: " << secure_str_literal << std::endl;
    
    const wchar_t* secure_wstr_literal = SECURE_WSTR("This is a secure wide string");
    std::wcout << L"Secure wide string from macro: " << secure_wstr_literal << std::endl;

    std::cout << "\nCRYPT_START and CRYPT_END Macro Demo:" << std::endl;
    std::cout << "Before CRYPT_START" << std::endl;
    CRYPT_START
    std::cout << "Inside CRYPT_START block" << std::endl;
    CRYPT_END
    std::cout << "After CRYPT_END" << std::endl;
    
    Minus_class::ClearRuntimeKey(runtime_key);
    
    Sleep(30000);
    return 0;
}
