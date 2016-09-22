# Accountable Assertions

A proof-of-concept implementation of the accountable assertions scheme
introduced in the research paper
[Liar, Liar, Coins on Fire! — Penalizing Equivocation By Loss Of Bitcoins](https://crypsys.mmci.uni-saarland.de/projects/PenalizingEquivocation/penalizing.pdf) (22nd Conference on Computer and
Communications Security, ACM CCS 2015).

## Functionality
Accountable assertions are a cryptographc primitive similar to digital
signatures. Instead of only authenticating a message, they allow a user
holding a secret *assertion key* to assert a *statement* in a *context*.
The user should only assert one unique statement in each context. The
assertion of two contradicting (i.e., different) statements in the same
context, also called *equivocation*, is considered malicious.

To incentivize that the user does not equivocate, he is held accountable
in the following sense: If the user creates two assertions that assert
two different statements in the same in the same context, then everybody
can extract the user's secret assertion key from the two assertions.

The victims of the equivocation can now use this (no longer) secret
assertion key to penalize equivocator. For example, if the secret
assertion key is a Bitcoin secret key associated with some time-locked
Bitcoins, the equivocator can be forced to lose these Bitcoins to a
predetermined party.

See
[the paper](https://crypsys.mmci.uni-saarland.de/projects/PenalizingEquivocation/penalizing.pdf)
for a full description of the functionality provided by accountable assertions.

## Technical Details
This is a proof-of-concept implementation based on Elliptic Curve
Cryptography on the curve secp256k1, i.e., it is compatible with Bitcoin
keys.

It is written in C++ and depends on libsecp256k1 to perform elliptic
curve computations. However, it does not only rely on the API provided
by libsecp256k1 but also on internal functions. Consequently, the full
source code of libsecp256k1 is currently necessary to build the project.

## Dependencies
 * [libsecp256k1](https://github.com/bitcoin/secp256k1) (full source,
   commit a0d3b89dd6c7b11b5a1d2d91040cc5372399b6dc, see #1)
 * [Google Test](https://github.com/google/googletest/)
 * [cmake](https://cmake.org)

## Building and Usage
```
$ mkdir build
$ cd build
$ cmake ..
$ make
```

You can additionally pass the following options to `cmake`:
 * `-DCMAKE_BUILD_TYPE=debug` for a debug build
 * `-DACCA_CT_LEN=n` to set the size of a supported assertion context to `n`
   bytes. This parameter influences the running time and the probability that
   any assertion does not succeed; see
   [the paper](https://crypsys.mmci.uni-saarland.de/projects/PenalizingEquivocation/penalizing.pdf)
   for details. The default is 8 bytes.

To run tests and benchmarks, run `./authenticatortest`.

The `Authenticator` class is provided as an interface to be used in other projects.

## Copyright and License
Copyright 2015 Tim Ruffing <tim.ruffing@mmci.uni-saarland.de>

The project is licensed under the MIT License, see LICENSE.txt
