
#include <cstring>
#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <fstream>
#include <time.h>
#include <sstream>
#include <iterator>

#include "SHVE.h"
#include <string>
#include <filesystem>
#include <dirent.h>
#include <vector>

using namespace std;

struct pairStruct{string RuleID; string Action; string Field; int Offset; int OffsetCount; string ConditionNum; string Key;};

SHVE_TOKEN new_token[1500];

int fileSize;

int x = 0;

template <typename Out>
void split(const std::string &s, char delim, Out result) {
    std::istringstream iss(s);
    std::string item;
    while (std::getline(iss, item, delim)) {
        *result++ = item;
    }
}

std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, std::back_inserter(elems));
    return elems;
}

void predicateGen(struct pairStruct *newpair, size_t predicate_len,
                    const AES_KEY &key,
                    SHVE_TOKEN* token) {
    
    
    int64_t **predicate2[fileSize];
    int64_t TokenSize;

    int y = 0;

    int TokenPoint = 0;

    for(int i = 0; i < fileSize; i++) {
        printf("%s\n", "done1");
        y += 1;

        printf("%d\n", y);

        if(newpair[i].OffsetCount == -1 && newpair[i].Offset == -1) {
            printf("pcap_open_offline() failed:");
            TokenSize = 1500 - newpair[i].Key.length();
            //int *array = new int[size];
            

        } else if (newpair[i].OffsetCount == -1) {
            TokenSize = 1500 - newpair[i].Key.length() - newpair[i].Offset;
            

        } else {
            
            TokenSize = newpair[i].OffsetCount;
        }

        std::vector<std::string> ipnums = split(newpair[i].Key.c_str(), ' ');
        for (string randomName: ipnums) {
            printf("%s\n", randomName.c_str());
            int irandom = std::stoi (randomName,nullptr,16);
            printf("%d\n", irandom);
        }


        predicate2[i] = new int64_t*[TokenSize];

        

        for (int j = 0; j < TokenSize; j++) {
        //assign predicate
            predicate2[i][j] = new int64_t[1500];
            
            fill_n(predicate2[i][j], 1500, -1);

            std::vector<int> convertedIP;

            std::vector<std::string> ipnums = split(newpair[i].Key.c_str(), ' ');
            for (string randomName: ipnums) {
                printf("%s\n", randomName.c_str());
                int irandom = std::stoi (randomName,nullptr,16);
                printf("%d\n", irandom);
                convertedIP.emplace_back(irandom);
                
            }

            //think of how to integrate offset
            for (int k = 0; k < convertedIP.size(); k++){
                //assign pattern to predicate array
                if(newpair[i].Offset == -1) {
                    predicate2[i][j][j+k] = convertedIP[k];
                    
                    
                } else {
                    predicate2[i][j][j+k+newpair[i].Offset] = convertedIP[k];
                    
                }
                
                //shve_token_gen(predicate2[i][j], 1500, key, token+i);

            }

		    
            //generate token for each line of predicate2
            shve_token_gen(predicate2[i][j], 1500, key, token+TokenPoint);



            TokenPoint++;

    }
        
    }
    

    return; 
    
}

void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
    {
        int64_t attribute[1500];
        int64_t matched_predicate[1500];
        int64_t unmatched_predicate[1500];
        //int64_t new_predicate[1500];
        
        for (int i = 0; i < 1410; i++) {
            attribute[i] = packet[i];
        };

        AES_KEY user_key;

        long long key_value1 = 12354, key_value2 = 54321;

        block key_block = make_block(key_value1, key_value2);

        AES_set_encrypt_key(key_block, &user_key);

        // SHVE ciphertext
        block ciphertext[1500];
        shve_enc(attribute, 1500, user_key, ciphertext);

        //Predicate generation

        //for loop to match ciphertext to token
        for (int i = 0; i < 1500; i++) {
            cout << "SHVE Query Result (new predicate):"<< shve_query(ciphertext, &new_token[i]) << endl;
            //shve_query(ciphertext, &new_token[i]);

            if (shve_query(ciphertext, &new_token[i]) != 0) {
                x += 1;
                //exit(0);
            }
            
        };

        printf("%d\n", x);

    }

int main() {

    

    char errbuff[PCAP_ERRBUF_SIZE];
    
    pcap_t* packets;

    int64_t new_predicate[1500];

    AES_KEY user_key;

    long long key_value1 = 12354, key_value2 = 54321;

    block key_block = make_block(key_value1, key_value2);

    AES_set_encrypt_key(key_block, &user_key);

    ifstream pairFile;
    pairFile.open("MLgeneratedRules.pair");

    string strTmp;
    getline(pairFile, strTmp);

    // Convert str to an integer
    fileSize = stoi(strTmp, nullptr, 0) - 1;
    pairStruct newPair[fileSize];

    for(int i = 0; i < fileSize; i++) {
        std::getline(pairFile, newPair[i].RuleID);
        std::getline(pairFile, newPair[i].Action);
        std::getline(pairFile, newPair[i].Field);

        string Temp1;
        std::getline(pairFile, Temp1);
        newPair[i].Offset = std::stoi(Temp1);

        string Temp2;
        std::getline(pairFile, Temp2);
        newPair[i].OffsetCount = std::stoi(Temp2);
        
        std::getline(pairFile, newPair[i].ConditionNum);

        string Temp3;
        std::getline(pairFile, Temp3);

        //printf("%s\n", Temp3.c_str());
        newPair[i].Key = Temp3;
    }

    predicateGen(newPair, 1500, user_key, new_token);

    clock_t tStart = clock();
    
    // DIR           *dirp;
    // struct dirent *directory;

    // clock_t tStart = clock();
    // dirp = opendir("./pcaps/malware-pcaps/");
    // if (dirp)
    // {
    //     while ((directory = readdir(dirp)) != NULL)
    //     {
    //       //printf("%s\n", directory->d_name);
    //       string str1 = directory->d_name;
    //       printf("%s\n",str1.c_str());
    //       string testfile = "./pcaps/malware-pcaps/" + str1;
    //       printf("%s\n",testfile.c_str());
    //       string str2 = "..";
          
    //       if (str1 != "..") {
    //           if (str1 != ".") {
    //             printf("%s\n",testfile.c_str());
    //             packets = pcap_open_offline(testfile.c_str(), errbuff);
    //                 if (packets == NULL) {
    //                     printf("pcap_open_offline() failed: %s\n", errbuff);
    //                     return 1;
    //                 }

    //                 printf("%s\n", "done");

    //                 //predicateGen(newPair, 1500, user_key, new_token);

    //                 printf("%s\n", "done4");

    //                 pcap_loop (packets, -1, my_callback, NULL);   /* main loop */
    //                 pcap_close (packets);
    //         }
    //       }
    //     }

    //     closedir(dirp);
    // }
    

    packets = pcap_open_offline("./pcaps/malware-pcaps/Zeus.pcap", errbuff);
    if (packets == NULL) {
        printf("pcap_open_offline() failed: %s\n", errbuff);
        return 1;
    }

    pcap_loop(packets, -1, my_callback, NULL);   /* main loop */
    pcap_close(packets);
    

    printf("%d\n", x);

    printf("Time taken: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);

}



