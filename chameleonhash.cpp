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

#include "chameleonhash.h"

#include <vector>
#include <algorithm>

void ChameleonHash::initialize()
{
    // the following two initialization functions
    // ensure already by themselves that they do their work only once
    secp256k1_ecmult_gen_start();
    secp256k1_ecmult_start();
}


ChameleonHash::ChameleonHash(const pk_t& pk) : hasSecretKey_(false)
{
    secp256k1_ge_t pkge;

    initialize();

    // secp256k1_eckey_pubkey_parse makes sure that the public key is valid, i.e.,
    // an affine group element
    if (!secp256k1_eckey_pubkey_parse(&pkge, pk.data(), pk.size())) {
        throw std::invalid_argument("not a valid public key");
    }

    secp256k1_gej_set_ge(&this->pk, &pkge);
}


ChameleonHash::ChameleonHash(const sk_t &sk) : hasSecretKey_(true)
{
    initialize();

    secp256k1_scalar_set_b32(&this->sk, sk.data(), nullptr);
    if (secp256k1_scalar_is_zero(&this->sk)) {
        throw std::invalid_argument("zero is not a valid secret key");
    }
    // compute public key
    secp256k1_ecmult_gen(&this->pk, &this->sk);

    secp256k1_scalar_inverse(&this->skInv, &this->sk);
}

ChameleonHash::pk_t ChameleonHash::getPk(bool compressed)
{
    secp256k1_ge_t pkge;
    secp256k1_ge_set_gej_var(&pkge, &this->pk);

    pk_t res;
    res.resize(65);
    int size;
    secp256k1_eckey_pubkey_serialize(&pkge, res.data(), &size,  compressed);
    res.resize(size);
    return res;
}

ChameleonHash::sk_t ChameleonHash::getSk()
{
    if (!hasSecretKey_) {
        throw std::logic_error("no secret key available");
    }
    sk_t res;
    secp256k1_scalar_get_b32(res.data(), &this->sk);
    return res;
}



void ChameleonHash::ch(hash_t& res, const digest_t& m, const rand_t& r)
{
    // m cannot overflow, this is ensured by the public ch() method
    secp256k1_scalar_t ms;
    secp256k1_scalar_set_b32(&ms, m.data(), nullptr);

    int overflow;

    secp256k1_scalar_t rs;
    secp256k1_scalar_set_b32(&rs, r.data(), &overflow);
    if (overflow) {
        throw std::invalid_argument("overflow in randomness");
    }

    secp256k1_gej_t resgej;
    secp256k1_ge_t resge;

    int hash_len = 0;

    if (this->hasSecretKey_) {
        // now we (ab)use the rs variable to compute the result
        secp256k1_scalar_mul(&rs, &rs, &this->sk);
        secp256k1_scalar_add(&rs, &rs, &ms);
        secp256k1_ecmult_gen(&resgej, &rs);
    }
    else {
        secp256k1_ecmult(&resgej, &this->pk, &rs, &ms);
    }
    secp256k1_ge_set_gej(&resge, &resgej);

    if (!secp256k1_eckey_pubkey_serialize(&resge, res.data(), &hash_len, 1) || hash_len != HASH_LEN) {
        throw std::logic_error("cannot serialize chameleon hash");
    }
}

void ChameleonHash::ch(hash_t& res, const mesg_t& m, const rand_t& r)
{
    digest_t d;
    digest(d, m);
    ch(res, d, r);
}

void ChameleonHash::extract(const mesg_t& m1, const rand_t& r1, const mesg_t& m2, const rand_t& r2) {
    digest_t d1, d2;
    digest(d1, m1);
    digest(d2, m2);
    extract(d1, r1, d2, r2);
}

void ChameleonHash::extract(const digest_t& d1, const rand_t& r1, const mesg_t& m2, const rand_t& r2) {
    digest_t d2;
    digest(d2, m2);
    extract(d1, r1, d2, r2);
}


void ChameleonHash::extract(const mesg_t& m1, const rand_t& r1, const digest_t& d2, const rand_t& r2) {
    digest_t d1;
    digest(d1, m1);
    extract(d1, r1, d2, r2);
}


void ChameleonHash::extract(const digest_t& d1, const rand_t& r1, const digest_t& d2, const rand_t& r2)
{
    // verify that the input is indeed a collision
    hash_t ch1, ch2;
    ch(ch1, d1, r1);
    ch(ch2, d2, r2);
    if ((r1 == r2 && d1 == d2) || ch1 != ch2) {
        throw std::invalid_argument("not a collision");
    }

    // Overflows in the following secp256k1_scalar_set_b32 calls
    // would have been already caught by ch() evaluation above.

    // d1+sk*r1 == d2+sk*r2 ==> 1/sk = (r1-r2)/(d2-d1)
    secp256k1_scalar_t tmp;
    secp256k1_scalar_t r1s;

    // set this->sk_inv = 1/(d2-d1)
    secp256k1_scalar_set_b32(&this->skInv, d1.data(), nullptr);
    secp256k1_scalar_negate(&this->skInv, &this->skInv);
    secp256k1_scalar_set_b32(&tmp, d2.data(), nullptr);
    secp256k1_scalar_add(&this->skInv, &this->skInv, &tmp);
    secp256k1_scalar_inverse_var(&this->skInv, &this->skInv);

    // set tmp = r2-r1
    secp256k1_scalar_set_b32(&tmp, r2.data(), nullptr);
    secp256k1_scalar_negate(&tmp, &tmp);
    secp256k1_scalar_set_b32(&r1s, r1.data(), nullptr);
    secp256k1_scalar_add(&tmp, &tmp, &r1s);

    // set this->sk_inv = (r1-r2)/(d2-d1)
    secp256k1_scalar_mul(&this->skInv, &this->skInv, &tmp);

    // set this->sk = 1/sk_inv
    secp256k1_scalar_inverse(&this->sk, &this->skInv);

    hasSecretKey_ = true;
}

void ChameleonHash::collision(const ChameleonHash::digest_t& d1, const ChameleonHash::rand_t& r1, const ChameleonHash::digest_t& d2, ChameleonHash::rand_t& r2)
{
    if (!hasSecretKey()) {
        throw std::logic_error("no secret key available");
    }

    // r2 = (d1-d2+sk*r1)/sk = (d1-d2)/sk + r1

    secp256k1_scalar_t rs2, tmp;
    int overflow;

    // set r2 = d1-d2
    secp256k1_scalar_set_b32(&rs2, d1.data(), &overflow);
    if (overflow) {
        throw std::domain_error("overflow for digest of message 1");
    }
    secp256k1_scalar_set_b32(&tmp, d2.data(), &overflow);
    if (overflow) {
        throw std::domain_error("overflow for digest of message 2");
    }
    secp256k1_scalar_negate(&tmp, &tmp);
    secp256k1_scalar_add(&rs2, &rs2, &tmp);

    // set r2 = (d1-d2)/sk
    secp256k1_scalar_mul(&rs2, &rs2, &skInv);

    // set r2 = (d1-d2)/sk + r1
    secp256k1_scalar_set_b32(&tmp, r1.data(), &overflow);
    if (overflow) {
        throw std::domain_error("overflow for randomness 1");
    }
    secp256k1_scalar_add(&rs2, &rs2, &tmp);

    secp256k1_scalar_get_b32(r2.data(), &rs2);
}

void ChameleonHash::collision(const ChameleonHash::mesg_t& m1, const ChameleonHash::rand_t& r1, const ChameleonHash::mesg_t& m2, ChameleonHash::rand_t& r2)
{
    digest_t d1, d2;
    digest(d1, m1);
    digest(d2, m2);
    collision(d1, r1, d2, r2);
}

void ChameleonHash::collision(const ChameleonHash::mesg_t& m1, const ChameleonHash::rand_t& r1, const ChameleonHash::digest_t& d2, ChameleonHash::rand_t& r2)
{
    digest_t d1;
    digest(d1, m1);
    collision(d1, r1, d2, r2);
}

void ChameleonHash::collision(const ChameleonHash::digest_t& d1, const ChameleonHash::rand_t& r1, const ChameleonHash::mesg_t& m2, ChameleonHash::rand_t& r2)
{
    digest_t d2;
    digest(d2, m2);
    collision(d1, r1, d2, r2);
}


void ChameleonHash::digest(digest_t &digest, const mesg_t &m)
{
    secp256k1_sha256_t sha;
    secp256k1_scalar_t ms;

    const unsigned char* in = m.data();
    size_t size = m.size();

    int overflow;
    do {
        secp256k1_sha256_initialize(&sha);
        secp256k1_sha256_write(&sha, in, size);
        secp256k1_sha256_finalize(&sha, digest.data());
        secp256k1_scalar_set_b32(&ms, digest.data(), &overflow);
        in = digest.data();
        size = digest.size();
    }
    while(overflow);
}

void ChameleonHash::digest(digest_t& digest, const ChameleonHash::hash_t& in1, const ChameleonHash::hash_t& in2)
{
    secp256k1_sha256_t hash;
    secp256k1_sha256_initialize(&hash);
    secp256k1_sha256_write(&hash, in1.data(), in1.size());
    secp256k1_sha256_write(&hash, in2.data(), in2.size());
    secp256k1_sha256_finalize(&hash, digest.data());
}

void ChameleonHash::randomOracle(hash_t& out, const hash_t& in1, const rand_t& in2)
{
    secp256k1_hmac_sha256_t hmac;
    unsigned char key[] = "RandomOracleGRandomOracleGRandom";
    secp256k1_hmac_sha256_initialize(&hmac, key, 32);
    secp256k1_hmac_sha256_write(&hmac, in1.data(), in1.size());
    secp256k1_hmac_sha256_write(&hmac, in2.data(), in2.size());
    secp256k1_hmac_sha256_finalize(&hmac, out.data());
    out[32] = '\0';
}
