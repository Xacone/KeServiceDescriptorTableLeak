#include <ntifs.h>

int contains_bytes_bitwise(UINT64 address, const UINT8* bytes, size_t num_bytes) {

    for (int i = 0; i < 8; ++i) {
        UINT8 current_byte = (address >> (i * 8)) & 0xFF;

        for (size_t j = 0; j < num_bytes; ++j) {
            if (current_byte == bytes[j]) {
                return 1;
            }
        }
    }
    return 0;
}

int contains_signature(ULONGLONG address, size_t memory_size, const UINT8* signature, size_t signature_size) {
    const UINT8* memory = (const UINT8*)address;

    if (signature_size > memory_size) {
        return 0;
    }

    for (size_t i = 0; i <= memory_size - signature_size; ++i) {
        int match = 1;
        for (size_t j = 0; j < signature_size; ++j) {
            if (memory[i + j] != signature[j]) {
                match = 0;
                break;
            }
        }
        if (match) {
            return 1;
        }
    }

    return 0;
}