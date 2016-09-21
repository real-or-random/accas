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

#include "node.h"
#include <assert.h>

Node::Node(const Authenticator::ct_t& ct) : level(Authenticator::DEPTH), fromLeft({})
{
    // Parse as big endian number
    for (size_t i = 0; i < Authenticator::CT_LEN; i++) {
        fromLeft[LIMBS - 1 - i/sizeof(limb_t)]
            |= (limb_t) ct[Authenticator::CT_LEN-i-1] << (i % sizeof(limb_t) * 8);
    }
}

Node::Node(size_t level, uint64_t fromLeft) : level(level), fromLeft({})
{
    this->fromLeft.back() += fromLeft;
}

Node Node::leftChildOfRoot()
{
    return Node(1, 0);
}

bool Node::moveToParent()
{
    if (isRoot()) {
        return false;
    }
    level--;

    // fL >>= 1, where fL is the integer represented by the bytes of fromLeft
    for (auto it = fromLeft.end() - 1; it != fromLeft.begin() ; it--) {
        *it = (*it >> 1) | ((*(it-1) & 1) << (8*sizeof(limb_t) - 1));
    }
    fromLeft[0] >>= 1;

#ifndef NDEBUG
    {
        limb_t allor = 0;
        for (auto limb : fromLeft) {
            allor |= limb;
        }
        assert(!isRoot() || allor == 0);
    }
#endif
    return true;
}

bool Node::moveToSibling()
{
    if (isRoot()) {
        return false;
    }
    fromLeft.back() ^= 1;
    return true;
}

bool Node::isLeftChild()
{
    if (isRoot()) {
        throw std::logic_error("Root node is not a child.");
    }
    return !(fromLeft.back() & 1);
}

bool Node::isRoot()
{
    return level == 0;
}

void Node::toBytes(Prf::data_t& d)
{
    d.resize(sizeof level + sizeof(limb_t) * LIMBS);
    d.push_back(level);
    for (auto &limb : fromLeft) {
        // for i = sizeof(limb_t) - 1, ..., 0
        for (size_t i = sizeof(limb_t) - 1; i-- > 0; ) {
            d.push_back((limb >> (i*8)) & 0xFF);
        }
    }
}
