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

#ifndef CHAMELEONHASH_H
#define CHAMELEONHASH_H

#include "secp256k1-macros.h"

#include "secp256k1/src/util.h"
#include "secp256k1/src/num.h"
#include "secp256k1/src/field.h"
#include "secp256k1/src/group.h"
#include "secp256k1/src/scalar.h"
#include "secp256k1/src/ecmult.h"
#include "secp256k1/src/ecmult_gen.h"
#include "secp256k1/src/eckey.h"
#include "secp256k1/src/hash.h"

#include "secp256k1/src/num_impl.h"
#include "secp256k1/src/field_impl.h"
#include "secp256k1/src/group_impl.h"
#include "secp256k1/src/scalar_impl.h"
#include "secp256k1/src/ecmult_impl.h"
#include "secp256k1/src/ecmult_gen_impl.h"
#include "secp256k1/src/eckey_impl.h"
#include "secp256k1/src/hash_impl.h"

#include <array>
#include <vector>

class ChameleonHash
{
public:
    static const size_t MESG_LEN = 32;
    static const size_t RAND_LEN = 32;
    static const size_t HASH_LEN = 33;
    static const size_t SK_LEN   = 32;

    // fixed-length message
    typedef std::array<unsigned char, MESG_LEN> digest_t;
    // arbitrary-length message
    typedef std::vector<unsigned char> mesg_t;
    typedef std::array<unsigned char, RAND_LEN> rand_t;
    typedef std::array<unsigned char, HASH_LEN> hash_t;
    // compressed or uncompressed public key
    typedef std::vector<unsigned char> pk_t;
    // secret key
    typedef std::array<unsigned char, SK_LEN> sk_t;

    ChameleonHash(const sk_t& sk);
    ChameleonHash(const pk_t& pk);
    bool hasSecretKey() {
        return hasSecretKey_;
    }

    pk_t getPk(bool compressed);
    sk_t getSk();

    void ch(hash_t& res, const mesg_t& m, const rand_t& r);
    void ch(hash_t& res, const digest_t& m, const rand_t& r);

    void extract(const digest_t& d1, const rand_t& r1, const digest_t& d2, const rand_t& r2);
    void extract(const mesg_t& m1, const rand_t& r1, const digest_t& d2, const rand_t& r2);
    void extract(const digest_t& d1, const rand_t& r1, const mesg_t& m2, const rand_t& r2);
    void extract(const mesg_t& m1, const rand_t& r1, const mesg_t& m2, const rand_t& r2);

    void collision(const digest_t& d1, const rand_t& r1, const digest_t& d2, rand_t& r2);
    void collision(const digest_t& d1, const rand_t& r1, const mesg_t& m2, rand_t& r2);
    void collision(const mesg_t& m1, const rand_t& r1, const digest_t& d2, rand_t& r2);
    void collision(const mesg_t& m1, const rand_t& r1, const mesg_t& m2, rand_t& r2);

    static void digest(digest_t& digest, const mesg_t& m);
    static void digest(digest_t& digest, const hash_t& in1, const hash_t& in2);
    static void randomOracle(ChameleonHash::hash_t& out, const ChameleonHash::hash_t& in1, const ChameleonHash::rand_t& in2);

private:
    secp256k1_gej_t pk;
    secp256k1_scalar_t sk;
    secp256k1_scalar_t skInv;
    bool hasSecretKey_;

    static void initialize();
};

#endif // CHAMELEONHASH_H
