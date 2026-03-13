// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hmp/commitment.h>
#include <hmp/seal.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <version.h>

#include <cstdint>
#include <exception>
#include <stdexcept>

#include <test/fuzz/fuzz.h>

namespace {

const BasicTestingSetup* g_setup;

void initialize_hmp_deserialize()
{
    static const auto testing_setup = MakeNoLogFileContext<>();
    g_setup = testing_setup.get();
}

struct invalid_fuzzing_input_exception : public std::exception {
};

template <typename T>
void DeserializeFromFuzzingInput(FuzzBufferType buffer, T& obj)
{
    CDataStream ds(buffer, SER_NETWORK, INIT_PROTO_VERSION);
    try {
        int version;
        ds >> version;
        ds.SetVersion(version);
    } catch (const std::ios_base::failure&) {
        throw invalid_fuzzing_input_exception();
    }
    try {
        ds >> obj;
    } catch (const std::ios_base::failure&) {
        throw invalid_fuzzing_input_exception();
    }
}

} // namespace

#define FUZZ_TARGET_HMP_DESERIALIZE(name, code)                    \
    FUZZ_TARGET(name, .init = initialize_hmp_deserialize)          \
    {                                                              \
        try {                                                      \
            code                                                   \
        } catch (const invalid_fuzzing_input_exception&) {         \
        }                                                          \
    }

FUZZ_TARGET_HMP_DESERIALIZE(sealshare_deserialize, {
    CSealShare share;
    DeserializeFromFuzzingInput(buffer, share);
})
FUZZ_TARGET_HMP_DESERIALIZE(assembled_seal_deserialize, {
    CAssembledSeal seal;
    DeserializeFromFuzzingInput(buffer, seal);
})
FUZZ_TARGET_HMP_DESERIALIZE(pubkeycommit_deserialize, {
    CPubKeyCommit commit;
    DeserializeFromFuzzingInput(buffer, commit);
})
