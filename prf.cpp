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

#include "prf.h"
#include "node.h"

#include <assert.h>

const unsigned char Prf::X = 'X';
const unsigned char Prf::R = 'R';

Prf::Prf(Prf::key_t key) : key(key) { }

Prf::Prf(ChameleonHash::sk_t dsk, bool extract) : key(key) {
    if (extract) {
        secp256k1_sha256_t hash;
        secp256k1_sha256_initialize(&hash);
        secp256k1_sha256_write(&hash, dsk.data(), dsk.size());
        assert(KEY_LEN == 256/8);
        secp256k1_sha256_finalize(&hash, this->key.data());
    }
}

void Prf::getX(Prf::out_t& x, Node& i)
{
    Prf::data_t ibytes;
    i.toBytes(ibytes);
    get_random_with_prefix(x, ibytes, X);
}

void Prf::getR(Prf::out_t& r, Node& i)
{
    Prf::data_t ibytes;
    i.toBytes(ibytes);
    get_random_with_prefix(r, ibytes, R);
}

void Prf::get_random_with_prefix(out_t& x, const data_t& data, const unsigned char& prefix)
{
    secp256k1_hmac_sha256_initialize(&hash, key.data(), key.size());
    secp256k1_hmac_sha256_write(&hash, &prefix, 1);
    secp256k1_hmac_sha256_write(&hash, data.data(), data.size());;
    secp256k1_hmac_sha256_finalize(&hash, x.data());
}
