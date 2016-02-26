/*
 * Copyright (c) 2015 Tim Ruffing <tim.ruffing@mmci.uni-saarland.de>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef PRF_H
#define PRF_H

#include "chameleonhash.h"

#include <assert.h>

#include "secp256k1/src/hash.h"
#include "secp256k1/src/hash_impl.h"

class Node;

class Prf
{
public:
    static const size_t KEY_LEN  = 32;
    static const size_t HASH_LEN = 32;

    typedef std::array<unsigned char, KEY_LEN> key_t;
    typedef std::array<unsigned char, HASH_LEN> out_t;
    typedef std::vector<unsigned char> data_t;

    Prf(key_t key);
    Prf(ChameleonHash::sk_t dsk, bool extract);

    void getX(out_t& x, Node& i);
    void getR(out_t& r, Node& i);

private:
    secp256k1_hmac_sha256_t hash;
    key_t key;

    static const unsigned char X;
    static const unsigned char R;
    void get_random_with_prefix(out_t& x, const data_t& data, const unsigned char& R);
};

#endif // PRF_H
