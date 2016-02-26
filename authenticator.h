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

#ifndef AUTHENTICATOR_H
#define AUTHENTICATOR_H

#include "chameleonhash.h"
#include "prf.h"

class Authenticator
{
public:
    static const size_t CT_LEN = 64/8;
    // depth is number of non-root levels
    static const size_t DEPTH  = CT_LEN*8;

    // Authentication tokens are 4160 bytes long. By compressing the sign bytes into bit vectors,
    // we could additionally save 60 bits.
    static const size_t TOKEN_LEN = DEPTH * (ChameleonHash::HASH_LEN + ChameleonHash::RAND_LEN);

    typedef std::array<unsigned char, CT_LEN> ct_t;
    typedef std::vector<unsigned char> st_t;

    typedef ChameleonHash::sk_t dsk_t;
    struct dpk_t {
        ChameleonHash::pk_t chpk;
        ChameleonHash::digest_t rootDigest;
    };

    struct token_t {
        std::array<ChameleonHash::hash_t, DEPTH> chs;
        std::array<ChameleonHash::rand_t, DEPTH> rs;
    };

    Authenticator(const Authenticator::dsk_t& dsk);
    Authenticator(const Authenticator::dpk_t& dpk);

    void authenticate(token_t& t, const ct_t& ct, const st_t &st);
    bool verify(const token_t& t, const ct_t& ct, const st_t &st);
    void extract(const token_t& t1, const token_t& t2, const ct_t& ct, const st_t& st1, const st_t& st2);

    Authenticator::dpk_t getDpk();
    Authenticator::dsk_t getDsk();


private:
    dsk_t dsk;
    ChameleonHash::digest_t rootDigest;

    ChameleonHash ch;
    bool hasSecretKey_;

    struct log_t {
        std::vector<ChameleonHash::hash_t> chs;
        std::vector<ChameleonHash::digest_t> xs;
    };
    bool verifyWithLog(const token_t& t, const ct_t& ct, const st_t &st, log_t* log);
};

#endif // AUTHENTICATOR_H
