#------------------------------------------------------------------------------
# Top-level CMake file for FISCO-BCOS.
# ------------------------------------------------------------------------------
# This file is part of FISCO-BCOS.
#
# FISCO-BCOS is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# FISCO-BCOS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with FISCO-BCOS.  If not, see <http://www.gnu.org/licenses/>
#
# (c) 2016-2018 fisco-dev contributors.
#------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.4)
set(FISCO_BCOS_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE PATH "The path to the cmake directory")
list(APPEND CMAKE_MODULE_PATH ${FISCO_BCOS_CMAKE_DIR})

project(FISCO-BCOS VERSION "2.2.0")
# Suffix like "-rc1" e.t.c. to append to versions wherever needed.
set(VERSION_SUFFIX "")


set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY On)

# basic setting
include(EthOptions)
include(EthCompilerSettings)
include(EthDependencies)

# install dependencies
include(ProjectCryptopp)
include(ProjectSecp256k1)
include(ProjectOpenSSL)
include(ProjectBoost)

include_directories("${CMAKE_SOURCE_DIR}" "evmc/include")

add_subdirectory(libdevcore)
add_subdirectory(libdevcrypto)
# generate executable binary fisco-bcos
add_subdirectory(crypto)

