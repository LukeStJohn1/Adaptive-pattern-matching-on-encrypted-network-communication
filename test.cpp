#include <cstring>
#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <fstream>
#include <time.h>

#include "SHVE.h"

#include <string>
#include <filesystem>
namespace fs = std::filesystem;

int main()
{
    std::string path = "/path/to/directory";
    for (const auto & entry : fs::directory_iterator(path))
        std::cout << entry.path() << std::endl;
}