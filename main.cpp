// Copyright (c) 2025 Manas
// All rights reserved.

#include<bits/stdc++.h>
using namespace std;

// Initial permutation table
const int IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

// Final permutation table
const int FP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

// Expansion table (expands 32 bits to 48 bits)
const int E[48] = {
    32, 1, 2, 3, 4, 5, 4, 5,
    6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27,
    28, 29, 28, 29, 30, 31, 32, 1
};

// S-boxes for the Feistel function
const int S[8][4][16] = {
    {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    {
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
    },
    {
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    {
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    },
    {
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    },
    {
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    },
    {
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    },
    {
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }
};

// P-box permutation
const int P[32] = {
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
};

// PC-1 - Permuted Choice 1 for key schedule
const int PC1[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
};

// PC-2 - Permuted Choice 2 for key schedule
const int PC2[48] = {
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
};

// Left shifts for key schedule
const int KEY_SHIFTS[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// Function to convert binary string to hexadecimal
string binaryToHex(const string& binary) {
    string hex = "";
    for (size_t i = 0; i < binary.length(); i += 4) {
        string chunk = binary.substr(i, 4);
        int decimal = 0;
        for (size_t j = 0; j < chunk.length(); j++) {
            decimal = decimal * 2 + (chunk[j] - '0');
        }
        if (decimal < 10)
            hex += ('0' + decimal);
        else
            hex += ('A' + decimal - 10);
    }
    return hex;
}

// Function to convert hexadecimal to binary string
string hexToBinary(const string& hex) {
    string binary = "";
    for (size_t j = 0; j < hex.length(); j++) {
        char c = hex[j];
        int val;
        if (c >= '0' && c <= '9')
            val = c - '0';
        else if (c >= 'A' && c <= 'F')
            val = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f')
            val = c - 'a' + 10;
        else
            continue;

        for (int i = 3; i >= 0; i--) {
            binary += ((val >> i) & 1) ? '1' : '0';
        }
    }
    return binary;
}

// Function to convert plaintext string to binary
string textToBinary(const string& text) {
    string binary = "";
    for (size_t i = 0; i < text.length(); i++) {
        char c = text[i];
        for (int j = 7; j >= 0; j--) {
            binary += ((c >> j) & 1) ? '1' : '0';
        }
    }
    return binary;
}

// Function to convert binary to plaintext string
string binaryToText(const string& binary) {
    string text = "";
    for (size_t i = 0; i < binary.length(); i += 8) {
        string byte = binary.substr(i, 8);
        char c = 0;
        for (size_t j = 0; j < byte.length(); j++) {
            c = (c << 1) | (byte[j] - '0');
        }
        text += c;
    }
    return text;
}

// Generate a random 64-bit key with proper parity
string generateRandomKey() {
    string key = "";
    srand(time(NULL));
    
    // Generate 56 random bits
    for (int i = 0; i < 56; i++) {
        key += (rand() % 2) ? '1' : '0';
    }
    
    // Insert parity bits (every 8th bit)
    string keyWithParity = "";
    for (int i = 0; i < 8; i++) {
        string block = key.substr(i * 7, 7);
        int ones = 0;
        for (size_t j = 0; j < block.length(); j++) {
            if (block[j] == '1') ones++;
        }
        // Add odd parity bit
        keyWithParity += block + ((ones % 2) ? '0' : '1');
    }
    
    return keyWithParity;
}

// Generate a random 64-bit initialization vector
string generateIV() {
    string iv = "";
    for (int i = 0; i < 64; i++) {
        iv += (rand() % 2) ? '1' : '0';
    }
    return iv;
}

// XOR two binary strings
string XOR(const string& a, const string& b) {
    string result = "";
    for (size_t i = 0; i < a.size() && i < b.size(); i++) {
        result += (a[i] == b[i]) ? '0' : '1';
    }
    return result;
}

// Function to permute using a given table
string permute(const string& input, const int* table, int size) {
    string output = "";
    for (int i = 0; i < size; i++) {
        if (table[i] - 1 < input.length()) {
            output += input[table[i] - 1];
        }
    }
    return output;
}

// Left circular shift for key generation
string leftCircularShift(const string& key, int shifts) {
    string result = key;
    for (int i = 0; i < shifts; i++) {
        char temp = result[0];
        result.erase(0, 1);
        result += temp;
    }
    return result;
}

// Generate subkeys from main key
vector<string> generateSubkeys(const string& key) {
    // Remove parity bits and apply PC-1
    string permutedKey = permute(key, PC1, 56);
    
    // Split into left and right halves
    string left = permutedKey.substr(0, 28);
    string right = permutedKey.substr(28, 28);
    
    vector<string> subkeys(16);
    
    // Create 16 subkeys through rotations and PC-2
    for (int i = 0; i < 16; i++) {
        // Perform left shifts according to schedule
        left = leftCircularShift(left, KEY_SHIFTS[i]);
        right = leftCircularShift(right, KEY_SHIFTS[i]);
        
        // Combine and apply PC-2
        string combined = left + right;
        subkeys[i] = permute(combined, PC2, 48);
    }
    
    return subkeys;
}

// S-box substitution
string sBoxSubstitution(const string& input) {
    string output = "";
    
    // Process 6-bit blocks through 8 S-boxes
    for (int i = 0; i < 8; i++) {
        string block = input.substr(i * 6, 6);
        
        // Calculate row and column
        int row = (block[0] - '0') * 2 + (block[5] - '0');
        int col = (block[1] - '0') * 8 + (block[2] - '0') * 4 + (block[3] - '0') * 2 + (block[4] - '0');
        
        // Get value from S-box
        int val = S[i][row][col];
        
        // Convert to 4-bit binary
        for (int j = 3; j >= 0; j--) {
            output += ((val >> j) & 1) ? '1' : '0';
        }
    }
    
    return output;
}

// Feistel function for DES
string feistelFunction(const string& right, const string& subkey) {
    // Expand right half from 32 to 48 bits
    string expanded = permute(right, E, 48);
    
    // XOR with subkey
    string xored = XOR(expanded, subkey);
    
    // Apply S-box substitution (48 to 32 bits)
    string substituted = sBoxSubstitution(xored);
    
    // Apply P-box permutation
    return permute(substituted, P, 32);
}

// Single round of DES
void desRound(string& left, string& right, const string& subkey) {
    string temp = right;
    right = XOR(left, feistelFunction(right, subkey));
    left = temp;
}

// Basic DES encryption (single block)
string DES_encrypt_block(const string& plaintext, const vector<string>& subkeys) {
    // Initial permutation
    string permutedText = permute(plaintext, IP, 64);
    
    // Split into left and right halves
    string left = permutedText.substr(0, 32);
    string right = permutedText.substr(32, 32);
    
    // 16 rounds of Feistel network
    for (int i = 0; i < 16; i++) {
        desRound(left, right, subkeys[i]);
    }
    
    // Swap left and right for final round (reverse order for decryption)
    string combined = right + left;
    
    // Final permutation
    return permute(combined, FP, 64);
}

// Basic DES decryption (single block)
string DES_decrypt_block(const string& ciphertext, const vector<string>& subkeys) {
    // Initial permutation
    string permutedText = permute(ciphertext, IP, 64);
    
    // Split into left and right halves
    string left = permutedText.substr(0, 32);
    string right = permutedText.substr(32, 32);
    
    // 16 rounds of Feistel network with reversed key order
    for (int i = 15; i >= 0; i--) {
        desRound(left, right, subkeys[i]);
    }
    
    // Swap left and right for final round
    string combined = right + left;
    
    // Final permutation
    return permute(combined, FP, 64);
}

// PKCS#5 padding
string addPadding(const string& data) {
    int blockSize = 64; // 64 bits
    int padLength = blockSize - (data.length() % blockSize);
    if (padLength == 0) {
        padLength = blockSize;
    }
    
    string padding = "";
    char padChar = static_cast<char>(padLength / 8); // Convert to bytes
    for (int i = 0; i < padLength; i++) {
        padding += (padChar & (1 << (7 - (i % 8)))) ? '1' : '0';
    }
    
    return data + padding;
}

// Remove PKCS#5 padding
string removePadding(const string& data) {
    if (data.empty()) return data;
    
    // Get the last byte (8 bits) to determine padding length
    string lastByte = data.substr(data.length() - 8);
    int padValue = 0;
    for (int i = 0; i < 8; i++) {
        padValue = (padValue << 1) | (lastByte[i] - '0');
    }
    
    // Calculate padding length in bits
    int padLength = padValue * 8;
    
    if (padLength > 0 && padLength <= data.length()) {
        return data.substr(0, data.length() - padLength);
    }
    
    return data; // Invalid padding, return original data
}

// DES CBC Mode encryption
string DES_CBC_encrypt(const string& plaintext, const string& key, const string& iv) {
    // Generate subkeys
    vector<string> subkeys = generateSubkeys(key);
    
    // Apply padding to ensure complete blocks
    string paddedText = addPadding(plaintext);
    
    string ciphertext = "";
    string prevBlock = iv;
    
    // Process each 64-bit block
    for (size_t i = 0; i < paddedText.length(); i += 64) {
        string block = paddedText.substr(i, 64);
        
        // XOR with previous ciphertext block (or IV for first block)
        string xoredBlock = XOR(block, prevBlock);
        
        // Encrypt the XORed block
        string encryptedBlock = DES_encrypt_block(xoredBlock, subkeys);
        
        // Add to ciphertext
        ciphertext += encryptedBlock;
        
        // Update previous block for next iteration
        prevBlock = encryptedBlock;
    }
    
    return ciphertext;
}

// DES CBC Mode decryption
string DES_CBC_decrypt(const string& ciphertext, const string& key, const string& iv) {
    // Generate subkeys
    vector<string> subkeys = generateSubkeys(key);
    
    string plaintext = "";
    string prevBlock = iv;
    
    // Process each 64-bit block
    for (size_t i = 0; i < ciphertext.length(); i += 64) {
        string block = ciphertext.substr(i, 64);
        
        // Decrypt the block
        string decryptedBlock = DES_decrypt_block(block, subkeys);
        
        // XOR with previous ciphertext block (or IV for first block)
        string xoredBlock = XOR(decryptedBlock, prevBlock);
        
        // Add to plaintext
        plaintext += xoredBlock;
        
        // Update previous block for next iteration
        prevBlock = block;
    }
    
    // Remove padding
    return removePadding(plaintext);
}

int main() {
    // Generate a random 64-bit key with proper parity
    
    // Initial Details
    cout<<"Name : Manas"<<endl<<"Regd No. : 12400217"<<endl<<"Project Name : CryptSecure"<<endl<<"Project Description : Take the input from user for the plain text. Encrypt the data using DES in CBC mode"<<endl 
	<<"Deliverables:"<<endl 
	<<"* Implement the encryption/decryption process."<<endl
	<<"* Key generation."<<endl<<endl;
    
    string key = generateRandomKey();
    cout << "Generated Key (Binary): " << key << endl;
    cout << "Generated Key (Hex): " << binaryToHex(key) << endl;
    
    // Generate initialization vector
    string iv = generateIV();
    cout << "Generated IV (Binary): " << iv << endl;
    cout << "Generated IV (Hex): " << binaryToHex(iv) << endl;
    
    // Get plaintext input
    cout << "Enter plaintext: ";
    string inputText;
    getline(cin, inputText);
    
    // Convert text to binary
    string binaryText = textToBinary(inputText);
    cout << "Binary plaintext: " << binaryText << endl;
    
    // Encrypt in CBC mode
    string ciphertext = DES_CBC_encrypt(binaryText, key, iv);
    cout << "Ciphertext (Binary): " << ciphertext << endl;
    cout << "Ciphertext (Hex): " << binaryToHex(ciphertext) << endl;
    
    // Decrypt in CBC mode
    string decryptedText = DES_CBC_decrypt(ciphertext, key, iv);
    cout << "Decrypted text (Binary): " << decryptedText << endl;
    cout << "Decrypted text: " << binaryToText(decryptedText) << endl;
    
    return 0;
}
