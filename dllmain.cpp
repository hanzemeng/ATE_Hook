#include "pch.h"
#include <fstream>
#include <windows.h>
#include <string>
#include <unordered_map>
#include <set>
using namespace std;

extern "C" __declspec(dllexport) void PluginThisLibrary() {};
ofstream log_file;

struct VectorHasher {
    int operator()(const vector<unsigned char>& V) const
    {
        long long p = 29791, m = 1e9 + 7;
        long long hash = 0;
        long long p_pow = 1;
        for (const unsigned char& i : V)
        {
            hash = (hash + i * p_pow) % m;
            p_pow = (p_pow * p) % m;
        }
        return hash;
    }
};
void print_vector(vector<unsigned char>& v)
{
    for (auto& i : v)
    {
        log_file << hex << (unsigned int)i << " ";
    }
    log_file << endl;
}
unordered_map<vector<unsigned char>, vector<unsigned char>, VectorHasher> dictionary;
bool setup_dictionary()
{
    string folder_name = "\Translation\\";
    vector<string> file_jp = { "common-jp", "0-1-jp", "0-2-jp", "1-jp", "2-jp", "3-jp", "4-jp", "5-jp", "6-jp", "7-jp", "8-jp", "9-jp", "10-jp", "11-jp", "12-jp", "13-jp", "14-jp", "15-jp", "16-jp", "17-jp", "TE-jp"};
    vector<string> file_cn = { "common-cn", "0-1-cn", "0-2-cn", "1-cn", "2-cn", "3-cn", "4-cn", "5-cn", "6-cn", "7-cn", "8-cn", "9-cn", "10-cn", "11-cn", "12-cn", "13-cn", "14-cn", "15-cn", "16-cn", "17-cn", "TE-cn" };

    for (int i = 0; i < file_cn.size(); i++)
    {
        log_file << "processing: " << (folder_name + file_jp[i]) << ", ";
        ifstream in_file_jp((folder_name + file_jp[i]).c_str(), std::ios::binary);
        ifstream in_file_cn((folder_name + file_cn[i]).c_str(), std::ios::binary);
        if (!in_file_jp.is_open() || !in_file_cn.is_open())
        {
            log_file << "failed to open translation files" << endl;
            continue;
        }

        char temp_char;

        while (!in_file_jp.eof())
        {
            vector<unsigned char> sentence_jp;
            sentence_jp.reserve(256);
            unsigned short pattern_checker = 0x0000;

            while (0x0100 != pattern_checker)
            {
                in_file_jp.get(temp_char);
                pattern_checker <<= 8;
                pattern_checker |= (unsigned char)temp_char;
                sentence_jp.push_back((unsigned char)temp_char);
            }
            in_file_jp.get(temp_char);
            in_file_jp.get(temp_char);
            sentence_jp.pop_back();
            sentence_jp.pop_back();

            vector<unsigned char> sentence_cn;
            sentence_cn.reserve(256);
            pattern_checker = 0x0000;

            while (0x0A0A != pattern_checker)
            {
                in_file_cn.get(temp_char);
                pattern_checker <<= 8;
                pattern_checker |= (unsigned char)temp_char;
                sentence_cn.push_back((unsigned char)temp_char);
            }
            sentence_cn.pop_back();
            sentence_cn.pop_back();

            int index = 0;
            int size = sentence_cn.size();
            while (index < size)
            {
                if (sentence_cn[index] < 0xA1 || sentence_cn[index] > 0xF7)
                {
                    index++;
                    continue;
                }
                if (0xA1 == sentence_cn[index])
                {
                    if (0xB8 == sentence_cn[index+1])
                    {
                        sentence_cn[index] = 0x81;
                        sentence_cn[index + 1] = 0x75;
                    }
                    else if (0xB9 == sentence_cn[index+1])
                    {
                        sentence_cn[index] = 0x81;
                        sentence_cn[index + 1] = 0x76;
                    }
                    else if (0xBE == sentence_cn[index+1])
                    {
                        sentence_cn[index] = 0x81;
                        sentence_cn[index + 1] = 0x79;
                    }
                    else if (0xBF == sentence_cn[index+1])
                    {
                        sentence_cn[index] = 0x81;
                        sentence_cn[index + 1] = 0x7A;
                    }
                }
                index += 2;
            }

            dictionary[sentence_jp] = sentence_cn;
        }

        in_file_jp.close();
        in_file_cn.close();

        log_file << "success" << endl;
    }
    return true;
}
bool setup_dictionary_selection()
{
    string folder_name = "\Translation\\";
    vector<string> file_jp = { "selection-jp" };
    vector<string> file_cn = { "selection-cn" };

    for (int i = 0; i < file_cn.size(); i++)
    {
        log_file << "processing: " << (folder_name + file_jp[i]) << ", ";
        ifstream in_file_jp((folder_name + file_jp[i]).c_str(), std::ios::binary);
        ifstream in_file_cn((folder_name + file_cn[i]).c_str(), std::ios::binary);
        if (!in_file_jp.is_open() || !in_file_cn.is_open())
        {
            log_file << "failed to open translation files" << endl;
            return false;
        }

        char temp_char;

        while (!in_file_jp.eof())
        {
            vector<unsigned char> sentence_jp;
            sentence_jp.reserve(256);
            unsigned short pattern_checker = 0x0000;

            while (0x0100 != pattern_checker)
            {
                in_file_jp.get(temp_char);
                pattern_checker <<= 8;
                pattern_checker |= (unsigned char)temp_char;
                sentence_jp.push_back((unsigned char)temp_char);
            }
            in_file_jp.get(temp_char);
            in_file_jp.get(temp_char);
            sentence_jp.pop_back();
            sentence_jp.pop_back();

            vector<unsigned char> sentence_cn;
            sentence_cn.reserve(256);
            pattern_checker = 0x0000;

            while (0x0100 != pattern_checker)
            {
                in_file_cn.get(temp_char);
                pattern_checker <<= 8;
                pattern_checker |= (unsigned char)temp_char;
                sentence_cn.push_back((unsigned char)temp_char);
            }
            in_file_cn.get(temp_char);
            in_file_cn.get(temp_char);
            sentence_cn.pop_back();
            sentence_cn.pop_back();


            dictionary[sentence_jp] = sentence_cn;
        }

        in_file_jp.close();
        in_file_cn.close();

        log_file << "success" << endl;
    }
    return true;
}

set<vector<unsigned char>> seen_sentence;
set<vector<unsigned char>> dup_sentence;
vector<vector<unsigned char>> all_sentence;

void write_address(char* start, unsigned long address)
{
    unsigned long temp = address;
    temp >>= 24;
    *(start + 3) = temp;
    temp = address;
    temp <<= 8;
    temp >>= 24;
    *(start + 2) = temp;
    temp = address;
    temp <<= 16;
    temp >>= 24;
    *(start + 1) = temp;
    temp = address;
    temp <<= 24;
    temp >>= 24;
    *(start + 0) = temp;
}
unsigned char translation_buffer[1024] = { 0x81, 0x79, 0x90, 0x86, 0x81, 0x7A, 0x90, 0x88, 0x90, 0x89, 0x01, 0x00 };
//char no_translation_found[14] = {'n', 'o', ' ', 't', 'r', 'a', 'n', 's', 'l', 'a', 't', 'i', 'o', 'n'};
char no_translation_found[12] = { 0xC3, 0xBB, 0xD3, 0xD0, 0xB6, 0xD4, 0xD3, 0xA6, 0xB7, 0xAD, 0xD2, 0xEB };

void translate_text(unsigned char* text)
{
    int index = 0;
    bool is_selection = false;
    if (*(text + index) == 0x12)
    {
        is_selection = true;
    }
    if (*(text + index) < 0x81 && !is_selection)
    {
        return;
    }

    vector<unsigned char> current_jp;
    current_jp.reserve(256);
    while (0x00 != *(text + index) && 0x01 != *(text + index))
    {
        current_jp.push_back(*(text + index));
        index++;
    }

    if (seen_sentence.end() != seen_sentence.find(current_jp))
    {
        dup_sentence.insert(current_jp);
    }
    else
    {
        seen_sentence.insert(current_jp);
        all_sentence.push_back(current_jp);
    }

    if (dictionary.find(current_jp) == dictionary.end())
    {
        memcpy(translation_buffer, no_translation_found, 12);
        if (is_selection)
        {
            translation_buffer[0] = 0x12;
            translation_buffer[1] = 0x31;
            translation_buffer[12] = 0x13;
            translation_buffer[13] = *(text + index);
            translation_buffer[14] = 0x00;
        }
        else
        {
            translation_buffer[12] = *(text + index);
            translation_buffer[13] = 0x00;
        }
    }
    else
    {
        vector<unsigned char> current_cn = dictionary[current_jp];
        memcpy(translation_buffer, &(current_cn[0]), current_cn.size());
        translation_buffer[current_cn.size()] = *(text + index);
        translation_buffer[current_cn.size() + 1] = 0x00;
    }


    //log_file << hex << (unsigned long)text << endl;
    // text = translation_buffer;
    void* temp = (void*)translation_buffer;
    __asm
    {
        push eax
        mov eax, temp
        mov [ebp + 8], eax
        pop eax
    }
}

char instuction_jump[7] = {0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3, 0x90};
char call_translate_text[100] = 
{
    0x50, 0x52, 0x51, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3, 0x59, 0x5A, 0x58, 0x51, 0x89, 0xf9,
    0xc6, 0x45, 0xfc, 0x11, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3
};

char create_font_jump[6] = { 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3 };
char call_create_font[100] = 
{
    0xC7, 0x40, 0x17, 0x86, 0x00, 0x00, 0x00, 0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0xFF, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3
};

char get_glyph_jump[8] = { 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3, 0x90, 0x90};
char call_get_glyph[100] =
{
    0x81, 0xF9, 0x79, 0x81, 0x00, 0x00, 0x74, 0x22, 0x81, 0xF9, 0x7A, 0x81, 0x00, 0x00, 0x74, 0x21, 0x81, 0xF9, 0x75, 0x81, 
    0x00, 0x00, 0x74, 0x20, 0x81, 0xF9, 0x76, 0x81, 0x00, 0x00, 0x74, 0x1F, 0x51, 0x52, 0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xEB, 0x1C, 0xB9, 0xBE, 0xA1, 0x00, 0x00, 0xEB, 0xEF, 0xB9, 0xBF, 0xA1, 0x00, 0x00, 0xEB, 0xE8, 0xB9, 0xB8, 0xA1, 0x00,
    0x00, 0xEB, 0xE1, 0xB9, 0xB9, 0xA1, 0x00, 0x00, 0xEB, 0xDA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3
};

char update_first_byte_check[9] = { 0x80, 0xF2, 0x00, 0x80, 0xC2, 0x7F, 0x80, 0xFA, 0x7D };

char call_translate_selection_text[100] =
{
    0x50, 0x52, 0x51, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3, 0x59, 0x5A, 0x58, 0x51, 0x8B, 0xCE,
    0xc6, 0x45, 0xfc, 0x01, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3
};


BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        log_file.open("ATE_log.txt");
        log_file << "game opened" << endl;
        if (!setup_dictionary() || !setup_dictionary_selection())
        {
            log_file << "failed to set up dictionary" << endl;
            return FALSE;
        }
        
        log_file << "succsefully set up dictionary" << endl;
        HMODULE Vm60 = GetModuleHandle(TEXT("Vm60"));
        HMODULE UnivUI = GetModuleHandle(TEXT("UnivUI"));

        unsigned long original_text_ptr = (unsigned long)Vm60 + 0xB5FCD;
        void (*translate_text_ptr)(unsigned char*) = translate_text;
        log_file << "original text function is at: " << hex << (unsigned long)original_text_ptr << endl;
        write_address(instuction_jump + 1, (unsigned long)call_translate_text);
        write_address(call_translate_text + 4, (unsigned long)call_translate_text+14);
        write_address(call_translate_text + 9, (unsigned long)translate_text_ptr);
        write_address(call_translate_text + 25, (unsigned long)original_text_ptr+7);
        DWORD old;
        if (!VirtualProtect((LPVOID)original_text_ptr, 7, PAGE_EXECUTE_READWRITE, &old))
        {
            log_file << "can't change protection" << endl;
            return FALSE;
        }
        memcpy((char*)original_text_ptr, instuction_jump, 7);
        if (!VirtualProtect((LPVOID)call_translate_text, 100, PAGE_EXECUTE_READWRITE, &old))
        {
            log_file << "can't change protection" << endl;
            return FALSE;
        }

        unsigned long original_create_font_ptr = (unsigned long)UnivUI + 0x3ABCD;
        log_file << "original create font function is at: " << hex << (unsigned long)original_create_font_ptr << endl;
        write_address(create_font_jump + 1, (unsigned long)call_create_font);
        if (!VirtualProtect((LPVOID)original_create_font_ptr, 6, PAGE_EXECUTE_READWRITE, &old))
        {
            log_file << "can't change protection" << endl;
            return FALSE;
        }
        memcpy(call_create_font + 9, (char*)original_create_font_ptr + 2, 4);
        write_address(call_create_font + 14, (unsigned long)original_create_font_ptr+6);
        memcpy((char*)original_create_font_ptr, create_font_jump, 6);
        if (!VirtualProtect((LPVOID)call_create_font, 100, PAGE_EXECUTE_READWRITE, &old))
        {
            log_file << "can't change protection" << endl;
            return FALSE;
        }

        unsigned long original_get_glyph_ptr = (unsigned long)UnivUI + 0x3AC23;
        log_file << "original get glyph function is at: " << hex << (unsigned long)original_get_glyph_ptr << endl;
        write_address(get_glyph_jump + 1, (unsigned long)call_get_glyph);
        if (!VirtualProtect((LPVOID)original_get_glyph_ptr, 8, PAGE_EXECUTE_READWRITE, &old))
        {
            log_file << "can't change protection" << endl;
            return FALSE;
        }
        memcpy(call_get_glyph + 36, (char*)original_get_glyph_ptr + 4, 4);
        write_address(call_get_glyph + 71, (unsigned long)original_get_glyph_ptr + 8);
        memcpy((char*)original_get_glyph_ptr, get_glyph_jump, 8);
        if (!VirtualProtect((LPVOID)call_get_glyph, 100, PAGE_EXECUTE_READWRITE, &old))
        {
            log_file << "can't change protection" << endl;
            return FALSE;
        }

        unsigned long original_first_byte_check_ptr = (unsigned long)Vm60 + 0x1E506;
        log_file << "original first byte check is at: " << hex << (unsigned long)original_first_byte_check_ptr << endl;
        if (!VirtualProtect((LPVOID)original_first_byte_check_ptr, 9, PAGE_EXECUTE_READWRITE, &old))
        {
            log_file << "can't change protection" << endl;
            return FALSE;
        }
        memcpy((char*)original_first_byte_check_ptr, update_first_byte_check, 9);
        
        unsigned long original_color_check_ptr = (unsigned long)Vm60 + 0xF15D;
        log_file << "original color byte check is at: " << hex << (unsigned long)original_color_check_ptr << endl;
        if (!VirtualProtect((LPVOID)original_color_check_ptr, 100, PAGE_EXECUTE_READWRITE, &old))
        {
            log_file << "can't change protection" << endl;
            return FALSE;
        }
        char update_original_color_check[10] = {0x80, 0xF2, 0x00, 0x80, 0xC2, 0x7F, 0x80, 0xFA, 0x1E, 0x00};
        memcpy((char*)original_color_check_ptr, update_original_color_check, 9);
        update_original_color_check[9] = update_original_color_check[8];
        update_original_color_check[8] = update_original_color_check[7];
        update_original_color_check[7] = update_original_color_check[6];
        update_original_color_check[6] = 0x41;
        original_color_check_ptr = (unsigned long)Vm60 + 0xF172;
        memcpy((char*)original_color_check_ptr, update_original_color_check, 10);
        original_color_check_ptr = (unsigned long)Vm60 + 0xF18D;
        memcpy((char*)original_color_check_ptr, update_original_color_check, 10);

        unsigned long original_color_check_2_ptr = (unsigned long)Vm60 + 0xF0A5;
        log_file << "original color byte check 2 is at: " << hex << (unsigned long)original_color_check_2_ptr << endl;
        if (!VirtualProtect((LPVOID)original_color_check_2_ptr, 7, PAGE_EXECUTE_READWRITE, &old))
        {
            log_file << "can't change protection" << endl;
            return FALSE;
        }
        char update_original_color_check_2[7] = { 0x34, 0x00, 0x04, 0x7F, 0x42, 0x3C, 0x1E };
        memcpy((char*)original_color_check_2_ptr, update_original_color_check_2, 7);
        
        unsigned long original_selection_text_ptr = (unsigned long)Vm60 + 0x1E08C;
        log_file << "original selection text function is at: " << hex << (unsigned long)original_selection_text_ptr << endl;
        write_address(instuction_jump + 1, (unsigned long)call_translate_selection_text);
        write_address(call_translate_selection_text + 4, (unsigned long)call_translate_selection_text + 14);
        write_address(call_translate_selection_text + 9, (unsigned long)translate_text_ptr);
        write_address(call_translate_selection_text + 25, (unsigned long)original_selection_text_ptr + 7);
        if (!VirtualProtect((LPVOID)original_selection_text_ptr, 7, PAGE_EXECUTE_READWRITE, &old))
        {
            log_file << "can't change protection" << endl;
            return FALSE;
        }
        memcpy((char*)original_selection_text_ptr, instuction_jump, 7);
        if (!VirtualProtect((LPVOID)call_translate_selection_text, 100, PAGE_EXECUTE_READWRITE, &old))
        {
            log_file << "can't change protection" << endl;
            return FALSE;
        }

        return TRUE;
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        log_file << "game ended" << endl;
        log_file.close();

        char temp[] = { 0x01, 0x00, 0x0a, 0x0a,0x0a };
        ofstream file("original_text", ios::out | ios::binary);
        for (vector<unsigned char>& i : all_sentence)
        {
            file.write((char*)&(i[0]), i.size());
            file.write(temp, 4);
        }
        
        file.write(temp+2, 3);
        for (auto& i : dup_sentence)
        {
            file.write((char*)&(i[0]), i.size());
            file.write(temp, 4);
        }
        file.close();
        return TRUE;
    }
    return TRUE;
}
