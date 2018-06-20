#include <iostream>
#include <stdlib.h>
#include <sstream>
#include <string>
#include <vector>
#include "Stream_Cipher.hpp"

/**
* Function maps a 16-bit input (V and c) to
* an 8-bit output (result). The function does
* a bit shift to the left. The function also
* xors with c if V's leftmost bit is 1.
*/
unsigned char Stream_Cipher::MULx(unsigned char V, unsigned char c)
{
    unsigned int result;
    if((V & 0x80) == 0x80)
    {
        V = (V << 1) & 0xFF;
        result = V ^ c;
    }
    else
    {
        result = (V << 1) & 0xFF;
    }
    return result;
}

/**
* Function maps a 16-bit input (V and c) to
* an 8-bit output (result). The function recursively
* calls MULx and MULy until i is 0.
*/
unsigned char Stream_Cipher::MULy(unsigned char V, int i, unsigned char c)
{
    if(i == 0)
    {
        return V;
    }
    else
    {
        return MULx(MULy(V,i-1,c), c);
    }
}

/**
* Function recieves 8-bit input, and calls the
* 4-different MULa cases specified by the assignment.
* The function then bit-shifts the values to their
* appropriate locations so when we return the value
* is r1 || r2 || r3 || r4 (32 bits).
*/
unsigned int Stream_Cipher::MULa(unsigned char c)
{
    unsigned int r1 = (MULy(c, 23, 0xA9) << 24);
    unsigned int r2 = (MULy(c, 245, 0xA9) << 16);
    unsigned int r3 = (MULy(c, 48, 0xA9) << 8);
    unsigned int r4 = MULy(c, 239, 0xA9);
    return (r1 | r2 | r3 | r4);
}

/**
* Function recieves 8-bit input, and calls the
* 4-different DIVa cases specified by the assignment.
* The function then bit-shifts the values to their
* appropriate locations so when we return the value
* is r1 || r2 || r3 || r4 (32 bits).
*/
unsigned int Stream_Cipher::DIVa(unsigned char c)
{
    unsigned int r1 = (MULy(c, 16, 0xA9) << 24);
    unsigned int r2 = (MULy(c, 39, 0xA9) << 16);
    unsigned int r3 = (MULy(c, 6, 0xA9) << 8);
    unsigned int r4 = MULy(c, 64, 0xA9);
    return (r1 | r2 | r3 | r4);
}

/**
* Function recieves an 8 bit input and produces an 8-bit
* output. The formula is as follows Srbox(x0*2^4 + x1)
* = y0^4 + y1. The function will pass back y0 || y1.
*/
unsigned char Stream_Cipher::Srbox(unsigned char x)
{
    unsigned char x0, x1;
    x0 = (x & 0xF0) >> 4;
    x1 = (x & 0x0F);
    return Sr[x0][x1];
}

/**
* Function recieves an 8 bit input and produces an 8-bit
* output. The formula is as follows Srbox(x0*2^4 + x1)
* = y0^4 + y1. The function will pass back y0 || y1.
*/
unsigned char Stream_Cipher::Sqbox(unsigned char x)
{
    unsigned char x0, x1;
    x0 = (x & 0xF0) >> 4;
    x1 = (x & 0x0F);
    return Sq[x0][x1];
}

/**
* Function maps 32-bit input w to 32-bit output result.
* The function will split w into 4 parts, w1 || w2 || w3 || w4.
* These values will then be used, along with the Sr table
* above to define r0, r1, r2, r3. These values will then
* be returned as r0 || r1 || r2 || r3 (32 bits).
*/
unsigned int Stream_Cipher::S1box(unsigned int w)
{
    unsigned int w0, w1, w2, w3;
    w0 = (w & 0xFF000000) >> 24;
    w1 = (w & 0x00FF0000) >> 16;
    w2 = (w & 0x0000FF00) >> 8;
    w3 = (w & 0x000000FF);
    
    unsigned int r0, r1, r2, r3;
    r0 = (MULx(Srbox(w0), 0x1B) ^ Srbox(w1) ^ Srbox(w2) ^ MULx(Srbox(w3), 0x1B) ^ Srbox(w3)) << 24;
    r1 = (MULx(Srbox(w0), 0x1B) ^ Srbox(w0) ^ MULx(Srbox(w1), 0x1B) ^ Srbox(w2) ^ Srbox(w3)) << 16;
    r2 = (Srbox(w0) ^ MULx(Srbox(w1), 0x1B) ^ Srbox(w1) ^ MULx(Srbox(w2), 0x1B) ^ Srbox(w3)) << 8;
    r3 = (Srbox(w0) ^ Srbox(w1) ^ MULx(Srbox(w2), 0x1B) ^ Srbox(w2) ^ MULx(Srbox(w3), 0x1B));
    return (r0 | r1 | r2 | r3);
}

/**
* Function maps 32-bit input w to 32-bit output result.
* The function will split w into 4 parts, w1 || w2 || w3 || w4.
* These values will then be used, along with the Sq table
* above to define r0, r1, r2, r3. These values will then
* be returned as r0 || r1 || r2 || r3 (32 bits).
*/
unsigned int Stream_Cipher::S2box(unsigned int w)
{
    unsigned int w0, w1, w2, w3;
    w0 = (w & 0xFF000000) >> 24;
    w1 = (w & 0x00FF0000) >> 16;
    w2 = (w & 0x0000FF00) >> 8;
    w3 = (w & 0x000000FF);
    
    unsigned int r0, r1, r2, r3;
    r0 = (MULx(Sqbox(w0), 0x69) ^ Sqbox(w1) ^ Sqbox(w2) ^ (MULx(Sqbox(w3), 0x69) ^ Sqbox(w3))) << 24;
    r1 = ((MULx(Sqbox(w0), 0x69) ^ Sqbox(w0)) ^ MULx(Sqbox(w1), 0x69) ^ Sqbox(w2) ^ Sqbox(w3)) << 16;
    r2 = (Sqbox(w0) ^ (MULx(Sqbox(w1), 0x69) ^ Sqbox(w1)) ^ MULx(Sqbox(w2), 0x69) ^ Sqbox(w3)) << 8;
    r3 = (Sqbox(w0) ^ Sqbox(w1) ^ (MULx(Sqbox(w2), 0x69) ^ Sqbox(w2)) ^ MULx(Sqbox(w3), 0x69));
    return (r0 | r1 | r2 | r3);
}

/**
* Function clocks the FSM.
*/
unsigned int Stream_Cipher::clockFSM()
{
    unsigned long long F, s, a, r;
    F = ((s15 + R1) & 0xFFFFFFFF) ^ R2;
    r = (R2 + (R3 ^ s5)) & 0xFFFFFFFF;
    R3 = S2box(R2);
    R2 = S1box(R1);
    R1 = r;
    return F;
}

/**
* Function clocks the LFSR in either initialization or keystream mode
*/
void Stream_Cipher::clockLFSR(unsigned int F, int mode)
{
    int v, s00, s01, s02, s03, s110, s111, s112, s113;
    s00 = (s0 & 0xFF000000) >> 24;
    s01 = (s0 & 0x00FF0000) << 8;
    s02 = (s0 & 0x0000FF00) << 8;
    s03 = (s0 & 0x000000FF) << 8;
    s110 = (s11 & 0xFF000000) >> 8;
    s111 = (s11 & 0x00FF0000) >> 8;
    s112 = (s11 & 0x0000FF00) >> 8;
    s113 = (s11 & 0x000000FF);
    
    if(mode == 1)
    {
        v = (s01 | s02 | s03) ^ MULa(s00) ^ s2 ^ (s110 | s111 | s112) ^ DIVa(s113) ^ F;
    }
    else
    {
        v = (s01 | s02 | s03) ^ MULa(s00) ^ s2 ^ (s110 | s111 | s112) ^ DIVa(s113);
    }
    
    s0 = s1;
    s1 = s2;
    s2 = s3;
    s3 = s4;
    s4 = s5;
    s5 = s6;
    s6 = s7;
    s7 = s8;
    s8 = s9;
    s9 = s10;
    s10 = s11;
    s11 = s12;
    s12 = s13;
    s13 = s14;
    s14 = s15;
    s15 = v;
}

/**
* Run Stream Cipher on input
*/
std::vector<std::string> Stream_Cipher::run_cipher(std::vector<std::string> keys, std::vector<std::string> IV, int n)
{    
    int i;
    unsigned int hex_val;
    std::vector<unsigned int> keys_hex, IVs_hex;
    for(i = 0; i < keys.size(); i++)
    {
        std::string s = keys.at(i);
        std::stringstream ss;
        ss << s;
        ss >> std::hex >> hex_val;
        keys_hex.push_back(hex_val);     
    }
    
    for(i = 0; i < IV.size(); i++)
    {
        std::string s = IV.at(i);
        std::stringstream ss;
        ss << s;
        ss >> std::hex >> hex_val;
        IVs_hex.push_back(hex_val);
    }
    
    s0 = keys_hex.at(0) ^ 0xFFFFFFFF;
    s1 = keys_hex.at(1) ^ 0xFFFFFFFF;
    s2 = keys_hex.at(2) ^ 0xFFFFFFFF;
    s3 = keys_hex.at(3) ^ 0xFFFFFFFF;
    s4 = keys_hex.at(0);
    s5 = keys_hex.at(1);
    s6 = keys_hex.at(2);
    s7 = keys_hex.at(3);
    s8 = keys_hex.at(0) ^ 0xFFFFFFFF; 
    s9 = keys_hex.at(1) ^ 0xFFFFFFFF ^ IVs_hex.at(3); 
    s10 = keys_hex.at(2) ^ 0xFFFFFFFF ^ IVs_hex.at(2); 
    s11 = keys_hex.at(3) ^ 0xFFFFFFFF; 
    s12 = keys_hex.at(0) ^ IVs_hex.at(1); 
    s13 = keys_hex.at(1); 
    s14 = keys_hex.at(2); 
    s15 = keys_hex.at(3) ^ IVs_hex.at(0);
    
    int F;
    R1 = R2 = R3 = 0;
    for(i = 0; i < 32; i++)
    {
        F = clockFSM();
        clockLFSR(F, 1);
    }
    
    clockFSM();
    clockLFSR(F, 0); 

    std::vector<unsigned int> results;
    for(i = 0; i < n; i++)
    {
        F = clockFSM();
        unsigned int r = F ^ s0;
        results.push_back(r);
        clockLFSR(F, 0);        
    }
    
    std::vector<std::string> encoded;
    for(i = 0; i < results.size(); i++)
    {
        std::stringstream ss;
        ss << std::hex << results.at(i);
        std::string s = ss.str();
        encoded.push_back(s);
    }
    
    return encoded;
}
