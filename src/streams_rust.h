// Copyright (c) 2024 The Kerrigan developers
// Distributed under the MIT software license.

#ifndef KERRIGAN_STREAMS_RUST_H
#define KERRIGAN_STREAMS_RUST_H

#include "hash.h"
#include "serialize.h"
#include "streams.h"

#include <rust/bridge.h>
#include <rust/cxx.h>

rust::Box<stream::CppStream> ToRustStream(RustDataStream& stream);
rust::Box<stream::CppStream> ToRustStream(CAutoFile& file);
rust::Box<stream::CppStream> ToRustStream(CBufferedFile& file);
rust::Box<stream::CppStream> ToRustStream(CHashWriter& writer);
rust::Box<stream::CppStream> ToRustStream(CSizeComputer& sc);

#endif // KERRIGAN_STREAMS_RUST_H
