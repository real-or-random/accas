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

#include <gtest/gtest.h>
#include "../chameleonhash.h"
#include "../authenticator.h"
#include <ctime>
#include <random>
#include <array>
#include <iomanip>

using namespace std;

class AuthenticatorTest : public ::testing::Test {
public:
    static const ChameleonHash::pk_t pk;
    static const ChameleonHash::sk_t sk;
    static random_device rd;
    static random_device::result_type seed;
    static mt19937_64 gen;

    static const int n = 1000;

    // some deterministic test messages
    static const ChameleonHash::mesg_t m1, m2;
    static const ChameleonHash::rand_t r1, r2;
    static const ChameleonHash::hash_t ch1;
    static const Authenticator::ct_t ct;

    static vector<ChameleonHash::mesg_t> xs;
    static vector<ChameleonHash::rand_t> rs;
    static vector<Authenticator::ct_t> cts;

    static void SetUpTestCase() {
        cout << "Random seed: " << seed << endl;
        uniform_int_distribution<> dis(0, 255);

        for (auto &x : xs) {
            x.resize(dis(gen));
            for (auto &c : x) {
                c = dis(gen);
            }
        }

        for (auto &r : rs) {
            for (auto &c : r) {
                c = dis(gen);
            }
        }

        for (auto &ct : cts) {
            for (auto &c : ct) {
                c = dis(gen);
            }
        }
    }
};

const ChameleonHash::pk_t AuthenticatorTest::pk = {
    0x03, 0x17, 0x0a, 0x37, 0x72, 0x41, 0xd9, 0x4a,
    0x5f, 0x4c, 0x85, 0xf1, 0x99, 0xc7, 0x96, 0xc5,
    0xa9, 0xf9, 0xf5, 0x6b, 0x3e, 0x2d, 0x6a, 0xea,
    0x18, 0xbe, 0x91, 0x88, 0xd1, 0x31, 0x31, 0x76,
    0x9c
};


// the corresponding secret exponent in big-endian
const ChameleonHash::sk_t AuthenticatorTest::sk = {
    0xb2, 0x19, 0x77, 0xc8, 0xca, 0x1c, 0xbb, 0x55,
    0xf0, 0xa3, 0xef, 0xfd, 0x99, 0x66, 0xe3, 0xd5,
    0xc9, 0x58, 0x86, 0x88, 0xfa, 0x02, 0xbf, 0x7a,
    0x0d, 0x2a, 0xf7, 0xb6, 0x36, 0x6f, 0x1e, 0x8f
};

const ChameleonHash::mesg_t AuthenticatorTest::m1 = {'a', 'b', 'c'};
const ChameleonHash::mesg_t AuthenticatorTest::m2 = {'1', '2', '3'};
const ChameleonHash::rand_t AuthenticatorTest::r1 = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};
const ChameleonHash::rand_t AuthenticatorTest::r2 = {
    0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
    0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
    0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
    0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8
};

const ChameleonHash::hash_t AuthenticatorTest::ch1 = {
    0x03,
    0x30, 0x61, 0x66, 0xa0, 0x5f, 0xa9, 0x8b, 0xab,
    0x22, 0x5b, 0xfa, 0x07, 0x79, 0x35, 0x7a, 0xed,
    0xa3, 0xcc, 0x1d, 0x08, 0x96, 0x2a, 0x17, 0x14,
    0x46, 0x55, 0xdf, 0xb6, 0x77, 0x06, 0x19, 0xc4
};

const Authenticator::ct_t AuthenticatorTest::ct = {
    // FIXME We always set the first 8 bytes even though CT_LEN can be configured.
    0x41, 0x04, 0xff, 0x17, 0x5f, 0xa9, 0x17, 0xab
};

random_device AuthenticatorTest::rd;
random_device::result_type AuthenticatorTest::seed = AuthenticatorTest::rd();
mt19937_64 AuthenticatorTest::gen(seed);
vector<ChameleonHash::mesg_t> AuthenticatorTest::xs(n);
vector<ChameleonHash::rand_t> AuthenticatorTest::rs(n);
vector<Authenticator::ct_t> AuthenticatorTest::cts(n);

TEST_F(AuthenticatorTest, ChSinglePk) {
    ChameleonHash ch(pk);
    ChameleonHash::hash_t res1;

    ch.ch(res1, m1, r1);
    EXPECT_EQ(res1, ch1);
}

TEST_F(AuthenticatorTest, ChSingleSk) {
    ChameleonHash ch(sk);
    ChameleonHash::hash_t res1;

    ch.ch(res1, m1, r1);
    EXPECT_EQ(res1, ch1);
}

TEST_F(AuthenticatorTest, NoCollisionWithoutSecretKey) {
    ChameleonHash ch(pk);
    ChameleonHash::rand_t r2;
    EXPECT_THROW(ch.collision(xs[0], rs[0], xs[0], r2), std::logic_error);
}


TEST_F(AuthenticatorTest, CollisionCorrectSingle) {
    ChameleonHash ch(sk);
    ChameleonHash::hash_t res1, res2;
    ChameleonHash::rand_t r2;

    ch.ch(res1, m1, r1);
    ch.collision(m1, r1, m2, r2);
    ch.ch(res2, m2, r2);
    EXPECT_EQ(res1, res2);
}

TEST_F(AuthenticatorTest, ExtractSingle) {
    // compute a collision
    ChameleonHash chsk(sk);
    ChameleonHash::rand_t r2;
    ChameleonHash::rand_t r2_;
    ChameleonHash::rand_t r1_;

    chsk.collision(m1, r1, m2, r2);

    // use the collision to extract the key, and recompute it
    ChameleonHash ch(pk);
    EXPECT_NO_THROW(ch.extract(m1, r1, m2, r2));
    ch.collision(m1, r1, m2, r2_);
    EXPECT_EQ(r2, r2_);

    ch.collision(m2, r2, m1, r1_);
    EXPECT_EQ(r1, r1_);
}

TEST_F(AuthenticatorTest, CollisionCorrectRandom) {
    ChameleonHash ch(sk);
    ChameleonHash::hash_t res1, res2;
    ChameleonHash::rand_t r2;

    for (int i = 1; i < n; i++) {
        ch.ch(res1, xs[i-1], rs[i-1]);
        ch.collision(xs[i-1], rs[i-1], xs[i], r2);
        ch.ch(res2, xs[i], r2);
        EXPECT_EQ(res1, res2) << "failed at index " << i;
    }
}

TEST_F(AuthenticatorTest, ChBenchmarkPublic) {
    ChameleonHash ch(pk);
    ChameleonHash::hash_t res;

    clock_t begin = clock();
    for (int i = 0; i < n; i++) {
        ch.ch(res, xs[i], rs[i]);
    }
    clock_t end = clock();

    double elapsed_usecs = double(end - begin) * 1000000 / (CLOCKS_PER_SEC * n);
    cout << n << " iterations " << endl;
    cout << elapsed_usecs << " microseconds on avg" << endl;
}

TEST_F(AuthenticatorTest, ChBenchmarkSecret) {
    ChameleonHash ch(sk);
    ChameleonHash::hash_t res;

    clock_t begin = clock();
    for (int i = 0; i < n; i++) {
        ch.ch(res, xs[i], rs[i]);
    }
    clock_t end = clock();

    double elapsed_usecs = double(end - begin) * 1000000 / (CLOCKS_PER_SEC * n);
    cout << n << " iterations " << endl;
    cout << elapsed_usecs << " microseconds on avg" << endl;
}

TEST_F(AuthenticatorTest, CollisionBenchmark) {
    ChameleonHash ch(sk);
    ChameleonHash::hash_t res1, res2;
    ChameleonHash::rand_t r2;

    clock_t begin = clock();
    for (int i = 1; i < n; i++) {
        ch.collision(xs[i-1], rs[i-1], xs[i], r2);
    }
    clock_t end = clock();

    double elapsed_usecs = double(end - begin) * 1000000 / (CLOCKS_PER_SEC * (n-1));
    cout << (n-1) << " iterations " << endl;
    cout << elapsed_usecs << " microseconds on avg" << endl;
}


TEST_F(AuthenticatorTest, AuthenticatorCorrectSingle) {
    Authenticator acca(sk);
    Authenticator::token_t t;

    acca.authenticate(t, ct, m1);
    EXPECT_TRUE(acca.verify(t, ct, m1));

    Authenticator::dpk_t dpk = acca.getDpk();
    Authenticator accaPk(dpk);
    EXPECT_TRUE(accaPk.verify(t, ct, m1));
}

TEST_F(AuthenticatorTest, AuthenticatorNonMalleableSingle) {
    Authenticator acca(sk);
    Authenticator::token_t t1, t2;

    acca.authenticate(t1, ct, m1);
    t2 = t1;
    t1.chs[Authenticator::DEPTH/2][ChameleonHash::HASH_LEN/2] ^= (1 << 5);
    EXPECT_FALSE(acca.verify(t1, ct, m1));
    t2.rs[Authenticator::DEPTH/2][ChameleonHash::RAND_LEN/2] ^= (1 << 5);
    EXPECT_FALSE(acca.verify(t2, ct, m1));
}

TEST_F(AuthenticatorTest, AuthenticatorExtractSimple) {
    Authenticator acca(sk);
    Authenticator::token_t t1, t2;
    acca.authenticate(t1, ct, m1);
    acca.authenticate(t2, ct, m2);

    Authenticator::dpk_t dpk = acca.getDpk();
    Authenticator accaPk(dpk);
    accaPk.extract(t1, t2, ct, m1, m2);
    EXPECT_EQ(sk, accaPk.getDsk());
}

TEST_F(AuthenticatorTest, AuthenticatorCorrectRandomAndBenchmark) {
    Authenticator acca(sk);
    std::vector<Authenticator::token_t> ts(n);
    cout << n << " iterations " << endl;
    {
        clock_t begin = clock();
        for (int i = 0; i < n; i++) {
            acca.authenticate(ts[i], cts[i], xs[i]);
        }
        clock_t end = clock();
        double elapsed_usecs = double(end - begin) * 1000000 / (CLOCKS_PER_SEC * n);

        cout << elapsed_usecs << " microseconds for authentication on avg" << endl;
    }
    {
        clock_t begin = clock();
        for (int i = 0; i < n; i++) {
            EXPECT_TRUE(acca.verify(ts[i], cts[i], xs[i]));
        }
        clock_t end = clock();

        double elapsed_usecs = double(end - begin) * 1000000 / (CLOCKS_PER_SEC * n);
        cout << elapsed_usecs << " microseconds for verification on avg" << endl;
    }
}
