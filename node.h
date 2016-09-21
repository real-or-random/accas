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

#ifndef NODE_H
#define NODE_H

#include "authenticator.h"
#include "prf.h"
#include <array>

class Node
{
public:
    // construct a leaf node
    Node(const Authenticator::ct_t& ct);
    static Node leftChildOfRoot();

    bool moveToParent();
    bool moveToSibling();
    bool isLeftChild();

    bool isRoot();
    void toBytes(Prf::data_t& d);

private:
    // Level 0 is the level of the root.
    size_t level;

    // The code is fully parametric in limb_t.
    typedef uint64_t limb_t;
    static const size_t LIMBS = (Authenticator::CT_LEN + sizeof(limb_t) - 1) / sizeof(limb_t);
    // Big-endian representation of number of other nodes on the same level left of this node.
    std::array<uint64_t, LIMBS> fromLeft = {};
    Node(size_t level, uint64_t fromLeft);
};


#endif // NODE_H
