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

Node::Node(const Authenticator::ct_t& ct) : level(Authenticator::DEPTH)
{
    // parse as big endian number
    fromLeft = ((uint64_t) ct[0] << 56) | ((uint64_t) ct[1] << 48) | ((uint64_t) ct[2] << 40) | ((uint64_t) ct[3] << 32)
    | ((uint64_t) ct[4] << 24) | ((uint64_t) ct[5] << 16) | ((uint64_t) ct[6] << 8) | (uint64_t) ct[7];
}

Node::Node(unsigned char level, uint64_t fromLeft) : level(level), fromLeft(fromLeft) { }

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
    fromLeft >>= 1;
    assert(!isRoot() || fromLeft == 0);
    return true;
}

bool Node::moveToSibling()
{
    if (isRoot()) {
        return false;
    }
    fromLeft ^= 1;
    return true;
}

bool Node::isLeftChild()
{
    if (isRoot()) {
        throw std::logic_error("Root node is not a child.");
    }
    return !(fromLeft & 1);
}

bool Node::isRoot()
{
    return level == 0;
}

void Node::toBytes(Prf::data_t& d)
{
    d.resize(1+8);
    d.push_back(level);
    for (int i = 1; i < 1+8; i++) {
        d.push_back(fromLeft >> ((8-i)*8) & 0xFF);
    }
}
