// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hmp/hmp_params.h>

#include <logging.h>
#include <rust/bridge.h>
#include <support/cleanse.h>

#include <cstring>

namespace hmp_proof {

bool InitParams()
{
    try {
        hmp::init_hmp_params();
        LogPrintf("HMP: Groth16 parameters initialized\n");
        return true;
    } catch (const std::exception& e) {
        LogPrintf("HMP: Groth16 parameter initialization failed: %s\n", e.what());
        return false;
    }
}

bool IsInitialized()
{
    return hmp::is_hmp_initialized();
}

std::vector<uint8_t> CreateProof(const uint8_t sk_bytes[32],
                                  const uint8_t block_hash[32],
                                  const uint8_t chain_state_hash[32])
{
    std::array<uint8_t, 32> sk_arr{};
    try {
        std::array<uint8_t, 32> bh_arr, cs_arr;
        memcpy(sk_arr.data(), sk_bytes, 32);
        memcpy(bh_arr.data(), block_hash, 32);
        memcpy(cs_arr.data(), chain_state_hash, 32);

        auto result = hmp::hmp_create_proof(sk_arr, bh_arr, cs_arr);
        memory_cleanse(sk_arr.data(), sk_arr.size());
        return std::vector<uint8_t>(result.begin(), result.end());
    } catch (const std::exception& e) {
        memory_cleanse(sk_arr.data(), sk_arr.size());
        LogPrintf("HMP: proof creation failed: %s\n", e.what());
        return {};
    }
}

bool VerifyProof(const std::vector<uint8_t>& proof,
                  const uint8_t block_hash[32],
                  const uint8_t commitment[32])
{
    try {
        std::array<uint8_t, 32> bh_arr, cm_arr;
        memcpy(bh_arr.data(), block_hash, 32);
        memcpy(cm_arr.data(), commitment, 32);

        rust::Slice<const uint8_t> proof_slice(proof.data(), proof.size());
        return hmp::hmp_verify_proof(proof_slice, bh_arr, cm_arr);
    } catch (const std::exception& e) {
        LogPrintf("HMP: proof verification failed: %s\n", e.what());
        return false;
    }
}

bool ComputeCommitment(const uint8_t sk_bytes[32],
                        const uint8_t block_hash[32],
                        const uint8_t chain_state_hash[32],
                        uint8_t out[32])
{
    std::array<uint8_t, 32> sk_arr{};
    try {
        std::array<uint8_t, 32> bh_arr, cs_arr;
        memcpy(sk_arr.data(), sk_bytes, 32);
        memcpy(bh_arr.data(), block_hash, 32);
        memcpy(cs_arr.data(), chain_state_hash, 32);

        auto result = hmp::hmp_compute_commitment(sk_arr, bh_arr, cs_arr);
        memory_cleanse(sk_arr.data(), sk_arr.size());
        memcpy(out, result.data(), 32);
        return true;
    } catch (const std::exception& e) {
        memory_cleanse(sk_arr.data(), sk_arr.size());
        LogPrintf("HMP: commitment computation failed: %s\n", e.what());
        return false;
    }
}

} // namespace hmp_proof
