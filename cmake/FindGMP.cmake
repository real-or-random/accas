# Copyright (c) 2008-2010 Kent State University
# Copyright (c) 2011-2012 Texas A&M University
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# FIXME: How do I find the version of GMP that I want to use?
# What versions are available?

# NOTE: GMP prefix is understood to be the path to the root of the GMP
# installation library.
set(GMP_PREFIX "" CACHE PATH "The path to the prefix of a GMP installation")


find_path(GMP_INCLUDE_DIR gmp.h
PATHS ${GMP_PREFIX}/include /usr/include /usr/local/include)

find_library(GMP_LIBRARY NAMES gmp
PATHS ${GMP_PREFIX}/lib /usr/lib /usr/local/lib)


if(GMP_INCLUDE_DIR AND GMP_LIBRARY)
get_filename_component(GMP_LIBRARY_DIR ${GMP_LIBRARY} PATH)
set(GMP_FOUND TRUE)
endif()

if(GMP_FOUND)
if(NOT GMP_FIND_QUIETLY)
MESSAGE(STATUS "Found GMP: ${GMP_LIBRARY}")
endif()
elseif(GMP_FOUND)
if(GMP_FIND_REQUIRED)
message(FATAL_ERROR "Could not find GMP")
endif()
endif()
