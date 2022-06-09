//
// Created by Shangqi on 13/8/21.
//

#ifndef PHM_SHVE_H
#define PHM_SHVE_H

#include <vector>

extern "C" {
#include "AES.h"
}

struct __attribute__((aligned(64))) shve_token_s {
    std::vector<int> S;
    block d0;
    block d1;
};

typedef struct shve_token_s SHVE_TOKEN;

void shve_token_gen(const int64_t* predicate, size_t predicate_len,
                 const AES_KEY &key,
                 SHVE_TOKEN *token);

void shve_enc(const int64_t* attribute, size_t attribute_len,
              const AES_KEY &key,
              block *ciphertext);

bool shve_query(const block* ciphertext,
                const SHVE_TOKEN *token);

#endif //PHM_SHVE_H
