#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include "Stream_Cipher.hpp"

std::vector<std::string> split(std::string list, std::string delimiter);

int main(int argc, char **argv)
{
    int i, n;
    std::string key_in;
    std::string iv_in;
    std::string output;
    if(argc == 5){
          n = atoi(argv[3]);
          key_in = argv[1];
          iv_in = argv[2];
          output = argv[4];
    }

    std::string key_line, iv_line;
    std::vector<std::string> keys, iv;

    std::ifstream infile_keys, infile_iv;
    infile_keys.open(key_in.c_str());
    infile_iv.open(iv_in.c_str());
    
    for(i = 0; i < 4; i++)
    {
        infile_keys >> key_line;
        keys.push_back(key_line);
    }
    
    for(i = 0; i < 4; i++)
    {
        infile_iv >> iv_line;
        iv.push_back(iv_line);
    }
    
    infile_keys.close();
    infile_iv.close();
    
    for(i=0; i<4; i++)
    {
        std::cout << keys.at(i) << " " << iv.at(i) << std::endl;
    }

    Stream_Cipher s;
    std::vector<std::string> results = s.run_cipher(keys, iv, n);
    
    std::ofstream fout(output);
    for(i = 0; i < results.size(); i++)
    {
        fout << results.at(i) << std::endl;
    }
    fout.close();
    
    return 0;
}
