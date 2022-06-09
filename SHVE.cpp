//
// Created by Shangqi on 27/8/21.
//

#include "SHVE.h"

void shve_token_gen(const int64_t* predicate, size_t predicate_len,
                    const AES_KEY &key,
                    SHVE_TOKEN* token) {
    // randomly generate the key on d0
    random_block(&token->d0);
    // set d1 to 0
    token->d1 = zero_block();
    // encrypt 0 with d0 and store it on d1
    AES_KEY predicate_key;
    AES_set_encrypt_key(token->d0, &predicate_key);
    AES_ecb_encrypt_blks(&token->d1, 1, &predicate_key);
    // generate random mask to mask d0
    for (int i = 0; i < predicate_len; i++) {
        // non-wildcard entry
        if (predicate[i] != - 1) {
            token->S.emplace_back(i);
            // create an encrypted block with predicate[i]|pos
            block pos_block = make_block((long long) predicate[i], (long long) i);
            AES_ecb_encrypt_blks(&pos_block, 1, &key);
            // xor it with d0
            token->d0 = block_xor(token->d0, pos_block);
        }
    }
}

void shve_enc(const int64_t* attribute, size_t attribute_len,
              const AES_KEY& key,
              block* ciphertext) {
    for (int i = 0; i < attribute_len; i++) {
        // create an encrypted block with predicate[i]|pos
        ciphertext[i] = make_block((long long) attribute[i], (long long) i);
    }
    AES_ecb_encrypt_blks(ciphertext, attribute_len, &key);
}

bool shve_query(const block* ciphertext,
                const SHVE_TOKEN* token) {
    block masked_key = token->d0;
    block predicate = token->d1;
    // retrieve non-wildcard entries to de-mask the key
    for (int i : token->S) {
        masked_key = block_xor(masked_key, ciphertext[i]);
    }
    // use recovered key to decrypt d1 and make predicate
    AES_KEY recovered_key;
    AES_set_decrypt_key(masked_key, &recovered_key);
    AES_ecb_decrypt_blks(&predicate, 1, &recovered_key);
    // return true when predicate == 0
    if (block_equal(predicate, zero_block())) {
        return true;
    } else {
        return false;
    }
}