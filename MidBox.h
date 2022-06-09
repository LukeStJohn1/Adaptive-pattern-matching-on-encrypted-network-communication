#ifndef __MID_BOX_H__
#define __MID_BOX_H__

#include <stdint.h>
#include <string>

using namespace std;

#define U32(p, offset) (*(uint32_t*)((char*)p + offset))
#define U64(p, offset) (*(uint64_t*)((char*)p + offset))

#define DEF_PADDING_COUNT 1

//Thrifht IP and Port
#define DEF_THRIFT_PORT 9090
#define DEF_THRIFT_IP "54.169.210.214"

//size of Trapdoor
#define NR_TRAPDOOR_BIT 128
#define NR_TRAPDOOR_CHAR 16

#define DEF_SECONDLINE_FLAG 123456

//size of public buf
#define DEF_BUF_LEN 256

//size of Key
#define NR_KEY_BIT 256
#define NR_KEY_CHAR 32

//Load of the Index
#define DEF_INDEX_LOAD 0.9

//the max times of kick out operator
#define DEF_MAX_KICKOUT 1024

//# of Entity per Block
#define DEF_ENTITY_NUM 4

//share memory Key
#define DEF_SHM_KEY 0x10086

#define DEF_MASTER_KEY "abcdefg0123456789x"

enum emIndexLine
{
    IDX_FIRST = 0,
    IDX_SECOND,
    NR_IDX_LINE
};

enum emKeyType
{
    KEY_TYPE_TRAPDOOR = 0,
    KEY_TYPE_MASK,
    KEY_PRF_RULEID,
    NR_KEY_TYPE
};

enum emAction
{
    EM_ACTION_ALERT = 1,
    EM_ACTION_LOG = 2,
    EM_ACTION_PASS = 3,
    EM_ACTION_ACTIVE = 4,
    EM_ACTION_DYNAMIC = 5,
    EM_ACTION_DROP = 6,
    EM_ACTION_REJECT = 7,
    EM_ACTION_SDROP = 8,
    NR_ENUM_ACTION
};

typedef struct stTrapdoor{

    char arTd[NR_IDX_LINE][NR_TRAPDOOR_CHAR];
    char arMask[NR_IDX_LINE][NR_TRAPDOOR_CHAR];

}Trapdoor;

typedef struct stQueryKey{
    char pTd[NR_TRAPDOOR_CHAR];
    char pMask[NR_TRAPDOOR_CHAR];
}QueryKey;

void BinaryXor(char *p, char *pSrc, char *pXor, uint32_t uiLen);

void BuildTrapdoor(Trapdoor *pTrapdoor, QueryKey *pQuery, char arKey[NR_KEY_TYPE][NR_KEY_CHAR], uint32_t uiC);

string AppendInt(char c, int i);




#endif