// Copyright (c) 2024 The Kerrigan developers
// Distributed under the MIT software license.

#include <sapling/sapling_init.h>

#include <logging.h>
#include <rust/bridge.h>

#include <atomic>
#include <string>

namespace sapling {

bool InitSaplingParams(const fs::path& spend_path, const fs::path& output_path)
{
    std::string spend_str = fs::PathToString(spend_path);
    std::string output_str = fs::PathToString(output_path);

    if (!fs::exists(spend_path)) {
        LogPrintf("ERROR: Sapling spend params not found: %s\n", spend_str);
        return false;
    }
    if (!fs::exists(output_path)) {
        LogPrintf("ERROR: Sapling output params not found: %s\n", output_str);
        return false;
    }

    try {
        ::sapling::init_sapling_params(spend_str, output_str);
    } catch (const std::exception& e) {
        LogPrintf("ERROR: Failed to load Sapling parameters: %s\n", e.what());
        return false;
    }

    LogPrintf("Sapling parameters loaded successfully from %s and %s\n",
              spend_str, output_str);
    return true;
}

bool IsSaplingInitialized()
{
    return ::sapling::is_sapling_initialized();
}

static std::atomic<AnchorCallback> g_anchor_callback{nullptr};

void SetAnchorCallback(AnchorCallback cb)
{
    g_anchor_callback.store(cb, std::memory_order_release);
}

bool GetBestAnchor(int nHeight, uint256& anchor)
{
    auto cb = g_anchor_callback.load(std::memory_order_acquire);
    if (!cb) return false;
    return cb(nHeight, anchor);
}

static std::atomic<FrontierCallback> g_frontier_callback{nullptr};

void SetFrontierCallback(FrontierCallback cb)
{
    g_frontier_callback.store(cb, std::memory_order_release);
}

bool GetFrontierData(int nHeight, std::vector<uint8_t>& data)
{
    auto cb = g_frontier_callback.load(std::memory_order_acquire);
    if (!cb) return false;
    return cb(nHeight, data);
}

static std::atomic<ValidAnchorCallback> g_valid_anchor_callback{nullptr};

void SetValidAnchorCallback(ValidAnchorCallback cb)
{
    g_valid_anchor_callback.store(cb, std::memory_order_release);
}

bool IsValidSaplingAnchor(const uint256& anchor)
{
    auto cb = g_valid_anchor_callback.load(std::memory_order_acquire);
    if (!cb) return false;
    return cb(anchor);
}

} // namespace sapling
