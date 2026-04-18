// Copyright (c) 2024 The Kerrigan developers
// Distributed under the MIT software license.

#include <wallet/rpc/sapling.h>

#include <algorithm>
#include <atomic>
#include <limits>
#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <evo/specialtx.h>
#include <core_io.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <logging.h>
#include <random.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <shutdown.h>
#include <rust/bridge.h>
#include <sapling/sapling_address.h>
#include <sapling/sapling_init.h>
#include <sapling/sapling_transaction_builder.h>
#include <sapling/sapling_tx_payload.h>
#include <support/cleanse.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <wallet/coincontrol.h>
#include <wallet/rpc/util.h>
#include <wallet/sapling_keymanager.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

namespace wallet {

RPCHelpMan z_getnewaddress()
{
    return RPCHelpMan{"z_getnewaddress",
        "\nReturns a new Sapling shielded payment address.\n"
        "If no Sapling spending key exists in the wallet, one is derived from the HD seed.\n",
        {},
        RPCResult{
            RPCResult::Type::STR, "address", "The new shielded address"
        },
        RPCExamples{
            HelpExampleCli("z_getnewaddress", "")
            + HelpExampleRpc("z_getnewaddress", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
            }

            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(*pwallet);

            auto& km = pwallet->GetSaplingKeyManager();

            // If no Sapling key exists, derive master spending key
            if (km.IsEmpty()) {
                SecureVector seed;

                // Try legacy wallet HD seed first, fall back to random seed
                LegacyScriptPubKeyMan* spk_man = pwallet->GetLegacyScriptPubKeyMan();
                if (spk_man) {
                    CHDChain hdChain;
                    if (spk_man->GetDecryptedHDChain(hdChain)) {
                        seed = hdChain.GetSeed();
                    }
                }

                if (seed.empty()) {
                    // Descriptor wallet or no HD chain, generate random seed
                    seed.resize(32);
                    GetStrongRandBytes(seed);
                }

                // Derive Sapling spending key via ZIP 32: m_Sapling / 32' / coin_type' / 0'
                rust::Slice<const uint8_t> seed_slice(seed.data(), seed.size());
                std::array<uint8_t, 169> xsk_bytes{};
                // RAII guard: cleanse xsk_bytes on every exit path, including an
                // exception thrown between intermediate FFI derivations. Without
                // this, a throw from xsk_derive after a successful xsk_master
                // would leave the master spending key material on the stack
                // uncleansed. Same pattern as the ZIP-32 derivation guards
                // introduced in commit b20703f (closes #1123).
                auto xsk_guard = std::unique_ptr<void, std::function<void(void*)>>(
                    (void*)1, [&](void*) { memory_cleanse(xsk_bytes.data(), xsk_bytes.size()); });
                try {
                    xsk_bytes = ::sapling::zip32::xsk_master(seed_slice);
                    xsk_bytes = ::sapling::zip32::xsk_derive(xsk_bytes, 32 | 0x80000000);
                    xsk_bytes = ::sapling::zip32::xsk_derive(xsk_bytes, uint32_t(Params().ExtCoinType()) | 0x80000000);
                    xsk_bytes = ::sapling::zip32::xsk_derive(xsk_bytes, 0 | 0x80000000);
                } catch (const std::exception& e) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Failed to derive Sapling spending key: %s", e.what()));
                }

                sapling::SaplingExtendedSpendingKey sk;
                sk.key = xsk_bytes;
                // xsk_bytes cleansed on scope exit via xsk_guard.

                // Capture master key for encrypted wallets
                CKeyingMaterial masterKey;
                if (km.IsCrypto() && !pwallet->IsLocked()) {
                    pwallet->WithEncryptionKey([&](const CKeyingMaterial& vk) {
                        masterKey = vk;
                        return true;
                    });
                }
                const CKeyingMaterial* pMasterKey = masterKey.empty() ? nullptr : &masterKey;

                WalletBatch batch(pwallet->GetDatabase());
                if (!km.AddSpendingKeyWithDB(batch, sk, pMasterKey)) {
                    memory_cleanse(sk.key.data(), sk.key.size());
                    memory_cleanse(masterKey.data(), masterKey.size() * sizeof(CKeyingMaterial::value_type));
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to add Sapling spending key");
                }
                memory_cleanse(sk.key.data(), sk.key.size());
                memory_cleanse(masterKey.data(), masterKey.size() * sizeof(CKeyingMaterial::value_type));
                pwallet->SetMinVersion(FEATURE_SAPLING);
            }

            auto addr = km.GenerateNewAddress();
            if (!addr) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to generate Sapling address");
            }

            WalletBatch batch(pwallet->GetDatabase());
            km.WriteAddressToDB(batch, *addr);
            km.WriteDiversifierIndexToDB(batch);

            return EncodeSaplingAddress(*addr);
        },
    };
}

RPCHelpMan z_getbalance()
{
    return RPCHelpMan{"z_getbalance",
        "\nReturns the balance of a shielded address.\n"
        "If no address is given, returns total shielded balance.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "The shielded address. If not provided, returns total shielded balance."},
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "Only include notes with at least this many confirmations."},
        },
        RPCResult{
            RPCResult::Type::STR_AMOUNT, "amount", "The total amount received at this address"
        },
        RPCExamples{
            HelpExampleCli("z_getbalance", "\"ks1...\"")
            + HelpExampleRpc("z_getbalance", "\"ks1...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            const auto& km = pwallet->GetSaplingKeyManager();

            int minconf = request.params[1].isNull() ? 1 : request.params[1].getInt<int>();
            if (minconf < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "minconf must be non-negative");
            }

            std::optional<sapling::SaplingPaymentAddress> filterAddr;
            if (!request.params[0].isNull()) {
                std::string addrStr = request.params[0].get_str();
                sapling::SaplingPaymentAddress addr;
                if (!DecodeSaplingAddress(addrStr, addr)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Sapling address");
                }
                if (!km.HaveAddress(addr)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Address not found in wallet");
                }
                filterAddr = addr;
            }

            auto notes = filterAddr ? km.GetUnspentNotes(*filterAddr) : km.GetUnspentNotes();
            int tipHeight = pwallet->GetLastBlockHeight();
            CAmount balance = 0;
            for (const auto& note : notes) {
                int confs = (note.blockHeight >= 0) ? (tipHeight - note.blockHeight + 1) : 0;
                if (confs >= minconf) {
                    if (!MoneyRange(balance + note.value)) {
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Sapling balance overflow");
                    }
                    balance += note.value;
                }
            }

            return ValueFromAmount(balance);
        },
    };
}

RPCHelpMan z_listunspent()
{
    return RPCHelpMan{"z_listunspent",
        "\nReturns an array of unspent shielded notes.\n",
        {
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "Minimum confirmations."},
            {"maxconf", RPCArg::Type::NUM, RPCArg::Default{9999999}, "Maximum confirmations."},
            {"addresses", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Filter by shielded addresses.",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A shielded address"},
                }
            },
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                        {RPCResult::Type::NUM, "outindex", "The output index"},
                        {RPCResult::Type::NUM, "confirmations", "The number of confirmations"},
                        {RPCResult::Type::STR, "address", "The shielded address"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "The amount of the note"},
                        {RPCResult::Type::STR_HEX, "memo", "The memo field (hex)"},
                        {RPCResult::Type::BOOL, "spendable", "Whether this note is spendable"},
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("z_listunspent", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            const auto& km = pwallet->GetSaplingKeyManager();

            int minconf = request.params[0].isNull() ? 1 : request.params[0].getInt<int>();
            int maxconf = request.params[1].isNull() ? 9999999 : request.params[1].getInt<int>();
            if (minconf < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "minconf must be non-negative");
            if (maxconf < minconf) throw JSONRPCError(RPC_INVALID_PARAMETER, "maxconf must be >= minconf");

            std::set<sapling::SaplingPaymentAddress> filterAddrs;
            if (!request.params[2].isNull()) {
                const UniValue& addrs = request.params[2].get_array();
                for (unsigned int i = 0; i < addrs.size(); i++) {
                    sapling::SaplingPaymentAddress addr;
                    if (!DecodeSaplingAddress(addrs[i].get_str(), addr)) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Sapling address: " + addrs[i].get_str());
                    }
                    filterAddrs.insert(addr);
                }
            }

            auto notes = km.GetUnspentNotes();
            int tipHeight = pwallet->GetLastBlockHeight();

            UniValue result(UniValue::VARR);
            for (const auto& note : notes) {
                int confs = (note.blockHeight >= 0) ? (tipHeight - note.blockHeight + 1) : 0;

                if (confs < minconf || confs > maxconf) continue;
                if (!filterAddrs.empty() && filterAddrs.count(note.recipient) == 0) continue;

                UniValue entry(UniValue::VOBJ);
                entry.pushKV("txid", note.txid.GetHex());
                entry.pushKV("outindex", note.outputIndex);
                entry.pushKV("confirmations", confs);
                entry.pushKV("address", EncodeSaplingAddress(note.recipient));
                entry.pushKV("amount", ValueFromAmount(note.value));
                entry.pushKV("memo", HexStr(note.memo));
                entry.pushKV("spendable", km.CanSpend(note.recipient));
                result.push_back(entry);
            }

            return result;
        },
    };
}

RPCHelpMan z_sendmany()
{
    return RPCHelpMan{"z_sendmany",
        "\nSend multiple amounts from a shielded or transparent address.\n"
        "Supports t->z, z->t, and z->z transfers. Use sendtoaddress/sendmany for t->t.\n",
        {
            {"fromaddress", RPCArg::Type::STR, RPCArg::Optional::NO, "The source address (transparent or shielded)."},
            {"amounts", RPCArg::Type::ARR, RPCArg::Optional::NO, "An array of destination objects.",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The destination address (transparent or shielded)."},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount to send."},
                            {"memo", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded memo (up to 512 bytes). Only for shielded recipients."},
                        },
                    },
                },
            },
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "Minimum confirmations for UTXOs/notes to use."},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Fee in KRGN. Default: base (0.0001) + 0.00005 per spend + 0.00005 per output."},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "txid", "The transaction id of the sent transaction"
        },
        RPCExamples{
            HelpExampleCli("z_sendmany", "\"KSvgmrG5YH1yXqRx99XzXphsvkQXpjdFxK\" "
                           "'[{\"address\":\"ks1...\",\"amount\":10.0}]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Reject shielded sends while the node is still catching up. The
            // wallet has not yet observed every block that may contain notes
            // spent by `fromaddress`, and broadcasting a Sapling transaction
            // exposes its nullifiers to peers. Waiting for IBD to finish is
            // the only way to avoid publishing a nullifier set that we may
            // not yet fully own.
            if (pwallet->chain().isInitialBlockDownload()) {
                throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD,
                    "Cannot send while in initial block download. Wait for sync to complete.");
            }

            // Make sure the results are valid at least up to the most recent block
            // the user could have gotten from another RPC command prior to now
            pwallet->BlockUntilSyncedToCurrentChain();

            // Hold cs_wallet only for input gathering (not during Groth16 proof generation).
            // Pattern: gather inputs under lock, release, build proof, reacquire, commit.
            std::unique_lock<RecursiveMutex> wallet_lock(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(*pwallet);

            if (!sapling::IsSaplingInitialized()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Sapling parameters not loaded. Start with -saplingparamdir=<dir>");
            }

            auto& km = pwallet->GetSaplingKeyManager();

            std::string fromStr = request.params[0].get_str();
            sapling::SaplingPaymentAddress fromSapling;
            bool fromIsShielded = DecodeSaplingAddress(fromStr, fromSapling);
            CTxDestination fromTransparent;
            if (!fromIsShielded) {
                fromTransparent = DecodeDestination(fromStr);
                if (!IsValidDestination(fromTransparent)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address");
                }
            }

            struct Recipient {
                bool isShielded;
                sapling::SaplingPaymentAddress saplingAddr;
                CTxDestination transparentDest;
                CAmount amount;
                std::vector<uint8_t> memo;
            };
            std::vector<Recipient> recipients;
            CAmount totalSend = 0;

            const UniValue& amounts = request.params[1].get_array();
            if (amounts.size() == 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "No recipients specified");
            }

            std::set<std::string> seenAddresses; // detect duplicate recipients
            for (unsigned int i = 0; i < amounts.size(); i++) {
                const UniValue& obj = amounts[i];
                Recipient r;

                std::string addrStr = obj["address"].get_str();
                if (!seenAddresses.insert(addrStr).second) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Duplicate recipient address: " + addrStr);
                }
                r.isShielded = DecodeSaplingAddress(addrStr, r.saplingAddr);
                if (!r.isShielded) {
                    r.transparentDest = DecodeDestination(addrStr);
                    if (!IsValidDestination(r.transparentDest)) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid recipient address: " + addrStr);
                    }
                }

                r.amount = AmountFromValue(obj["amount"]);
                if (r.amount <= 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount must be positive");
                }

                if (obj.exists("memo")) {
                    if (!r.isShielded) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Memo can only be sent to shielded addresses");
                    }
                    std::string memoStr = obj["memo"].get_str();
                    if (!IsHex(memoStr)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Memo must be a valid hex string");
                    }
                    r.memo = ParseHex(memoStr);
                    if (r.memo.size() > 512) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Memo too long (max 512 bytes)");
                    }
                }

                // Check BEFORE adding to prevent signed overflow UB
                if (r.amount > MAX_MONEY - totalSend) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Total send amount out of range");
                }
                totalSend += r.amount;
                recipients.push_back(std::move(r));
            }

            size_t nShieldedSpends = 0;
            size_t nShieldedOutputs = 0;
            for (const auto& r : recipients) {
                if (r.isShielded) nShieldedOutputs++;
            }

            int minconf = request.params[2].isNull() ? 1 : request.params[2].getInt<int>();
            if (minconf < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "minconf must be non-negative");
            }

            CAmount fee;
            if (!request.params[3].isNull()) {
                fee = AmountFromValue(request.params[3]);
                if (fee <= 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee must be positive");
                }
            } else {
                fee = SAPLING_BASE_FEE;
            }

            bool hasShielded = fromIsShielded || nShieldedOutputs > 0;

            if (!hasShielded) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "z_sendmany requires at least one shielded address (use sendtoaddress for t->t)");
            }

            const auto& chainparams = Params();
            const auto& params = chainparams.GetConsensus();
            int tipHeight = pwallet->GetLastBlockHeight();
            std::string netID = chainparams.NetworkIDString();

            std::array<uint8_t, 32> anchor{};
            {
                uint256 anchorHash;
                if (sapling::GetBestAnchor(tipHeight, anchorHash)) {
                    std::copy(anchorHash.begin(), anchorHash.end(), anchor.begin());
                }
            }

            SaplingTransactionBuilder builder(params, tipHeight + 1, anchor, netID);

            // Note cmus reserved for this tx; unreserved on completion.
            std::set<uint256> selectedCmus;

            // Transparent UTXOs locked during coin selection to prevent
            // concurrent z_sendmany from double-spending. Unlocked on
            // completion or error, same as the note reservation pattern.
            std::vector<COutPoint> lockedCoins;

            // Deferred registration of the internal diversified change address.
            // Populated when a change output is added to the builder; the actual
            // RegisterDiversifiedAddress call runs only after CommitTransaction
            // succeeds, so failed/aborted sends leave no orphan mapping in the
            // wallet DB (Patch E LoadNote self-heal still covers a crash in the
            // narrow commit-to-register window).
            std::optional<sapling::SaplingPaymentAddress> pendingChangeAddr;
            std::optional<sapling::SaplingIncomingViewingKey> pendingChangeIvk;

            if (fromIsShielded) {
                if (!km.CanSpend(fromSapling)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Don't have spending key for source address");
                }
                auto sk = km.GetSpendingKey(fromSapling);
                if (!sk) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Spending key not found");
                }
                // Cleanse spending key on all exit paths
                auto sk_guard = std::unique_ptr<void, std::function<void(void*)>>(
                    (void*)1, [&](void*) { if (sk) memory_cleanse(sk->key.data(), sk->key.size()); });

                auto allNotesKeyed = km.GetUnspentNotesWithKeys(fromSapling);
                std::vector<std::pair<uint256, SaplingNoteData>> notesKeyed;
                for (const auto& [cmu, note] : allNotesKeyed) {
                    int confs = (note.blockHeight >= 0) ? (tipHeight - note.blockHeight + 1) : 0;
                    if (confs >= minconf) {
                        notesKeyed.emplace_back(cmu, note);
                    }
                }
                std::vector<SaplingNoteData> notes;
                notes.reserve(notesKeyed.size());
                for (const auto& [cmu, nd] : notesKeyed) notes.push_back(nd);

                // Pre-calculate fee before coin selection using a convergence
                // loop.  The fee depends on the number of spends (which depends
                // on how many notes we select) and whether change exists (which
                // depends on the fee).  Iterate until stable.
                if (request.params[3].isNull()) {
                    CAmount prevFee = -1;
                    CAmount estimatedFee = CalculateSaplingFee(1, std::max(size_t{2}, nShieldedOutputs));
                    // Cap iterations to avoid infinite loop on pathological inputs.
                    for (int iter = 0; iter < 10 && estimatedFee != prevFee; ++iter) {
                        prevFee = estimatedFee;

                        // Select the minimum set of notes that covers totalSend + estimatedFee.
                        CAmount runningTotal = 0;
                        size_t estimatedSpends = 0;
                        for (const auto& note : notes) {
                            if (runningTotal >= totalSend + estimatedFee) break;
                            estimatedSpends++;
                            runningTotal += note.value;
                        }
                        if (estimatedSpends == 0) estimatedSpends = 1;

                        // Determine whether change will exist.
                        bool hasChange = (runningTotal > totalSend + estimatedFee);
                        // Builder pads outputs to min 2 for privacy
                        size_t totalOutputs = std::max(size_t{2}, nShieldedOutputs + (hasChange ? 1 : 0));

                        // Recompute fee with actual spend/output counts.
                        estimatedFee = CalculateSaplingFee(estimatedSpends, totalOutputs);
                    }
                    fee = estimatedFee;
                }

                CAmount noteTotal = 0;
                for (const auto& [cmu, note] : notesKeyed) {
                    if (noteTotal >= totalSend + fee) break;
                    nShieldedSpends++;
                    selectedCmus.insert(cmu);

                    if (note.witnessData.empty()) {
                        throw JSONRPCError(RPC_WALLET_ERROR,
                            "Note has no Merkle witness. Chain may not be synced or note not yet confirmed.");
                    }
                    std::array<uint8_t, 1065> merklePathArr;
                    try {
                        rust::Slice<const uint8_t> witSlice(note.witnessData.data(), note.witnessData.size());
                        auto witness = sapling::tree::witness_deserialize(witSlice);
                        auto merklePath = sapling::tree::witness_path(*witness);
                        if (merklePath.size() != 1065) {
                            throw std::runtime_error(strprintf("unexpected path size %d", merklePath.size()));
                        }
                        std::copy(merklePath.begin(), merklePath.end(), merklePathArr.begin());
                    } catch (const std::exception& e) {
                        throw JSONRPCError(RPC_WALLET_ERROR,
                            strprintf("Corrupted witness data for note. Resync wallet or wait for next block. (%s)", e.what()));
                    }

                    std::array<uint8_t, 43> recipientArr;
                    std::copy(note.recipient.d.begin(), note.recipient.d.end(), recipientArr.begin());
                    std::copy(note.recipient.pk_d.begin(), note.recipient.pk_d.end(), recipientArr.begin() + 11);

                    if (!builder.AddSaplingSpend(*sk, recipientArr, note.value, note.rseed, merklePathArr)) {
                        throw JSONRPCError(RPC_WALLET_ERROR,
                            "Failed to add Sapling spend (anchor mismatch or invalid witness)");
                    }
                    noteTotal += note.value;
                    if (!MoneyRange(noteTotal)) {
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Shielded balance overflow");
                    }
                }

                if (noteTotal < totalSend + fee) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                        strprintf("Insufficient shielded funds. Have %s, need %s",
                                  FormatMoney(noteTotal), FormatMoney(totalSend + fee)));
                }

                // Add change output back to an unlinkable internal address (ZIP 316).
                // Using the same address as the sender would allow trivial change
                // heuristic deanonymization.
                CAmount change = noteTotal - totalSend - fee;
                if (change > 0) {
                    // Get FVK + DK from sender address
                    auto fvk = km.GetFvk(fromSapling);
                    auto dk = km.GetDk(fromSapling);
                    if (!fvk || !dk) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot derive change address: missing FVK or DK");
                    }

                    // Derive internal FVK (unlinkable to external addresses) via ZIP 316
                    std::array<uint8_t, 96> fvk_bytes;
                    std::copy(fvk->ak.begin(), fvk->ak.end(), fvk_bytes.begin());
                    std::copy(fvk->nk.begin(), fvk->nk.end(), fvk_bytes.begin() + 32);
                    std::copy(fvk->ovk.begin(), fvk->ovk.end(), fvk_bytes.begin() + 64);

                    auto internalFvk = sapling::zip32::derive_internal_fvk(fvk_bytes, *dk);

                    // Derive a fresh diversified address from the internal FVK
                    std::array<uint8_t, 11> j_start{};
                    GetStrongRandBytes(Span{j_start.data(), 8});
                    auto internalAddr = sapling::zip32::find_address(internalFvk.fvk, internalFvk.dk, j_start);

                    // Use the sender's OVK so they can recover change (but not
                    // the external FVK's OVK; use the internal FVK's OVK to
                    // limit exposure). The internal OVK is derived from the
                    // internal FVK bytes [64..96].
                    std::array<uint8_t, 32> changeOvk;
                    std::copy(internalFvk.fvk.begin() + 64, internalFvk.fvk.begin() + 96, changeOvk.begin());

                    if (!builder.AddSaplingOutput(changeOvk, internalAddr.addr, change)) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to add shielded change output");
                    }
                    nShieldedOutputs++;

                    // Stash the change address + internal IVK. The mapping is
                    // persisted via RegisterDiversifiedAddress only AFTER
                    // CommitTransaction succeeds, so a send that fails to
                    // build, sign, or broadcast leaves nothing in the wallet
                    // DB. Recovery of the narrow commit-vs-register window
                    // is handled by LoadNote self-heal on next wallet load.
                    sapling::SaplingPaymentAddress changeAddr;
                    std::copy(internalAddr.addr.begin(), internalAddr.addr.begin() + 11, changeAddr.d.begin());
                    std::copy(internalAddr.addr.begin() + 11, internalAddr.addr.end(),   changeAddr.pk_d.begin());

                    sapling::SaplingIncomingViewingKey internalIvk;
                    try {
                        internalIvk.key = sapling::zip32::fvk_to_ivk(internalFvk.fvk);
                    } catch (const std::exception& e) {
                        throw JSONRPCError(RPC_WALLET_ERROR,
                            strprintf("Failed to derive internal IVK for change address: %s", e.what()));
                    }

                    pendingChangeAddr = changeAddr;
                    pendingChangeIvk = internalIvk;
                }

                // sk cleansed by sk_guard destructor
            } else {
                if (request.params[3].isNull()) {
                    fee = CalculateSaplingFee(0, std::max(size_t{2}, nShieldedOutputs));
                }

                CCoinControl coin_control;
                coin_control.m_min_depth = minconf;

                // Get available coins using AvailableCoinsListUnspent (only_spendable=false)
                // like listunspent does.  We already filter by sourceScript below, so the
                // only_spendable flag provides no additional safety and can incorrectly
                // exclude spendable UTXOs in descriptor wallets.
                CoinsResult available_coins = AvailableCoinsListUnspent(*pwallet, &coin_control);
                auto allCoins = available_coins.all();

                // Filter to only UTXOs belonging to the specified source address.
                // Without this, we'd spend UTXOs from all wallet addresses which
                // is a privacy leak and violates user expectation.
                CScript sourceScript = GetScriptForDestination(fromTransparent);
                allCoins.erase(
                    std::remove_if(allCoins.begin(), allCoins.end(),
                        [&sourceScript](const COutput& c) {
                            return c.txout.scriptPubKey != sourceScript;
                        }),
                    allCoins.end());

                CAmount sourceTotal = 0;
                for (const auto& coin : allCoins) {
                    if (!MoneyRange(sourceTotal + coin.txout.nValue)) {
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Transparent balance overflow");
                    }
                    sourceTotal += coin.txout.nValue;
                }

                if (sourceTotal < totalSend + fee) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                        strprintf("Insufficient transparent funds at %s. Have %s, need %s",
                                  EncodeDestination(fromTransparent),
                                  FormatMoney(sourceTotal), FormatMoney(totalSend + fee)));
                }

                CAmount transparentTotal = 0;

                std::sort(allCoins.begin(), allCoins.end(), [](const COutput& a, const COutput& b) {
                    return a.txout.nValue > b.txout.nValue;
                });

                for (const auto& coin : allCoins) {
                    if (transparentTotal >= totalSend + fee) break;
                    builder.AddTransparentInput(coin.outpoint, coin.txout.scriptPubKey, coin.txout.nValue);
                    pwallet->LockCoin(coin.outpoint);
                    lockedCoins.push_back(coin.outpoint);
                    transparentTotal += coin.txout.nValue;
                }

                if (transparentTotal < totalSend + fee) {
                    for (const auto& op : lockedCoins) pwallet->UnlockCoin(op);
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds after coin selection");
                }

                CAmount change = transparentTotal - totalSend - fee;
                CScript scriptChange = GetScriptForDestination(fromTransparent);
                CTxOut changeTxOut(change, scriptChange);
                if (change > 0 && !IsDust(changeTxOut, pwallet->chain().relayDustFee())) {
                    builder.AddTransparentOutput(scriptChange, change);
                } else if (change > 0) {
                    fee += change; // absorb dust into fee
                }
            }

            // Privacy fix: Do NOT apply the sender's OVK to external
            // recipient outputs. Using the sender's OVK on all outputs means
            // an FVK compromise reveals the full transaction history including
            // recipient details. Instead:
            //   - z->z: Use no OVK for external outputs (sender cannot decrypt
            //     outCiphertext after sending). Change already uses internal OVK.
            //   - t->z: Use no OVK (the transparent source has no meaningful OVK;
            //     previously all-zeros OVK let ANY observer decrypt outCiphertext).
            for (const auto& r : recipients) {
                if (r.isShielded) {
                    std::array<uint8_t, 43> toAddr;
                    std::copy(r.saplingAddr.d.begin(), r.saplingAddr.d.end(), toAddr.begin());
                    std::copy(r.saplingAddr.pk_d.begin(), r.saplingAddr.pk_d.end(), toAddr.begin() + 11);

                    // No OVK for external recipients, prevents FVK compromise
                    // from revealing who was paid and how much.
                    if (!builder.AddSaplingOutputNoOvk(toAddr, r.amount, r.memo)) {
                        for (const auto& op : lockedCoins) pwallet->UnlockCoin(op);
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to add shielded output");
                    }
                } else {
                    CScript scriptPubKey = GetScriptForDestination(r.transparentDest);
                    builder.AddTransparentOutput(scriptPubKey, r.amount);
                }
            }

            // Reserve selected notes before releasing the lock to prevent
            // concurrent z_sendmany from double-selecting the same notes.
            if (!selectedCmus.empty()) {
                km.ReserveNotes(selectedCmus);
            }

            // Release cs_wallet before Groth16 proof generation (slow, 1-30s).
            // All inputs have been collected above; the builder owns them now.
            wallet_lock.unlock();

            std::string buildError;
            auto mtx = builder.Build(&buildError);
            // Helper to unlock transparent coins. Needs cs_wallet held.
            auto unlockCoins = [&]() {
                for (const auto& op : lockedCoins) pwallet->UnlockCoin(op);
            };

            if (!mtx) {
                if (!selectedCmus.empty()) km.UnreserveNotes(selectedCmus);
                wallet_lock.lock();
                unlockCoins();
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build Sapling transaction: " + buildError);
            }

            CTransactionRef tx = MakeTransactionRef(std::move(*mtx));

            // 1. Context-independent validity checks (duplicate inputs, output
            //    ranges, vExtraPayload consistency, etc.)
            TxValidationState txState;
            if (!CheckTransaction(*tx, txState)) {
                if (!selectedCmus.empty()) km.UnreserveNotes(selectedCmus);
                wallet_lock.lock();
                unlockCoins();
                throw JSONRPCError(RPC_WALLET_ERROR,
                    strprintf("Sapling transaction failed validation: %s", txState.ToString()));
            }

            // 2. Size checks -- reject before broadcast rather than wasting
            //    minutes on Groth16 proofs only to be rejected by mempool.
            //    Check both payload size and total serialized tx size.
            if (tx->vExtraPayload.size() > MAX_SAPLING_TX_EXTRA_PAYLOAD) {
                if (!selectedCmus.empty()) km.UnreserveNotes(selectedCmus);
                wallet_lock.lock();
                unlockCoins();
                throw JSONRPCError(RPC_WALLET_ERROR,
                    strprintf("Sapling payload too large: %u bytes (max %u)",
                              tx->vExtraPayload.size(), MAX_SAPLING_TX_EXTRA_PAYLOAD));
            }
            if (GetSerializeSize(*tx) > MAX_STANDARD_TX_SIZE) {
                if (!selectedCmus.empty()) km.UnreserveNotes(selectedCmus);
                wallet_lock.lock();
                unlockCoins();
                throw JSONRPCError(RPC_WALLET_ERROR,
                    strprintf("Sapling transaction too large: %u bytes (max %u)",
                              GetSerializeSize(*tx), MAX_STANDARD_TX_SIZE));
            }

            wallet_lock.lock();

            // Check for reorg during proof generation -- anchor may be stale
            if (pwallet->GetLastBlockHeight() != tipHeight) {
                if (!selectedCmus.empty()) km.UnreserveNotes(selectedCmus);
                unlockCoins();
                throw JSONRPCError(RPC_WALLET_ERROR,
                    "Chain tip changed during proof generation -- anchor may be stale, please retry");
            }

            // Re-check unlock state -- wallet may have been locked
            // while we were building proofs without cs_wallet held.
            try {
                EnsureWalletIsUnlocked(*pwallet);
            } catch (...) {
                if (!selectedCmus.empty()) km.UnreserveNotes(selectedCmus);
                unlockCoins();
                throw;
            }

            // Sign transparent inputs (Sapling bundle is already signed by Build())
            if (!tx->vin.empty()) {
                CMutableTransaction mtxSign(*tx);
                if (!pwallet->SignTransaction(mtxSign)) {
                    if (!selectedCmus.empty()) km.UnreserveNotes(selectedCmus);
                    unlockCoins();
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign transparent inputs");
                }
                tx = MakeTransactionRef(std::move(mtxSign));
            }

            // 3. Fee sanity -- guard against accidental mega-fees
            if (fee > pwallet->m_default_max_tx_fee) {
                if (!selectedCmus.empty()) km.UnreserveNotes(selectedCmus);
                unlockCoins();
                throw JSONRPCError(RPC_WALLET_ERROR,
                    strprintf("Fee %s exceeds wallet maximum (%s). "
                              "Use -maxtxfee to raise the limit if intended.",
                              FormatMoney(fee), FormatMoney(pwallet->m_default_max_tx_fee)));
            }

            // CommitTransaction throws std::runtime_error on db failure;
            // let it propagate as a 500-level error to the caller.
            try {
                pwallet->CommitTransaction(tx, {}, {});
            } catch (...) {
                if (!selectedCmus.empty()) km.UnreserveNotes(selectedCmus);
                unlockCoins();
                throw;
            }

            // Mark notes spent synchronously before releasing reservation.
            // ScanSaplingSpends normally fires async via CValidationInterface;
            // calling it here closes the race window for concurrent z_sendmany.
            if (tx->nType == TRANSACTION_SAPLING) {
                auto payload = GetTxPayload<SaplingTxPayload>(tx->vExtraPayload);
                if (payload) {
                    WalletBatch batch(pwallet->GetDatabase());
                    km.ScanSaplingSpends(*tx, *payload, &batch);
                }
            }

            // Register the internal diversified change address now that the tx
            // is committed. A failure here leaves the mapping recoverable via
            // LoadNote self-heal on next wallet load; it is deliberately
            // non-fatal because the funds are safely spendable either way.
            if (pendingChangeAddr && pendingChangeIvk) {
                WalletBatch batch(pwallet->GetDatabase());
                if (!km.RegisterDiversifiedAddress(*pendingChangeAddr, *pendingChangeIvk, &batch)) {
                    LogPrintf("z_sendmany: failed to register internal change address (funds still spendable after next restart via LoadNote self-heal)\n");
                }
            }

            if (!selectedCmus.empty()) km.UnreserveNotes(selectedCmus);
            unlockCoins();

            return tx->GetHash().GetHex();
        },
    };
}

RPCHelpMan z_listaddresses()
{
    return RPCHelpMan{"z_listaddresses",
        "\nReturns the list of Sapling shielded addresses belonging to the wallet.\n",
        {},
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", "A shielded address"},
                        {RPCResult::Type::BOOL, "spendable", "Whether the wallet has the spending key"},
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("z_listaddresses", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            const auto& km = pwallet->GetSaplingKeyManager();
            auto addresses = km.GetAllAddresses();

            UniValue result(UniValue::VARR);
            for (const auto& addr : addresses) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("address", EncodeSaplingAddress(addr));
                entry.pushKV("spendable", km.CanSpend(addr));
                result.push_back(entry);
            }

            return result;
        },
    };
}

RPCHelpMan z_exportkey()
{
    return RPCHelpMan{"z_exportkey",
        "\nReveals the spending key corresponding to a shielded address.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The shielded address."},
        },
        RPCResult{
            RPCResult::Type::STR, "key", "The hex-encoded extended spending key (169 bytes)"
        },
        RPCExamples{
            HelpExampleCli("z_exportkey", "\"ks1...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(*pwallet);

            std::string addrStr = request.params[0].get_str();
            sapling::SaplingPaymentAddress addr;
            if (!DecodeSaplingAddress(addrStr, addr)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Sapling address");
            }

            const auto& km = pwallet->GetSaplingKeyManager();
            if (!km.HaveAddress(addr)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Address not found in wallet");
            }

            auto sk = km.GetSpendingKey(addr);
            if (!sk) {
                throw JSONRPCError(RPC_WALLET_ERROR, "No spending key available (watch-only address or wallet locked)");
            }

            std::string hexKey = HexStr(sk->key);
            memory_cleanse(sk->key.data(), sk->key.size());
            UniValue ret(hexKey);
            memory_cleanse(hexKey.data(), hexKey.size());
            // NOTE: UniValue internally copies the string; that copy cannot be
            // reliably cleansed because UniValue does not support secure
            // destruction. Acceptable for an RPC that explicitly exports
            // a secret; the caller already receives it over the wire.
            return ret;
        },
    };
}

RPCHelpMan z_importkey()
{
    return RPCHelpMan{"z_importkey",
        "\nImports a spending key for a shielded address.\n",
        {
            {"key", RPCArg::Type::STR, RPCArg::Optional::NO, "The hex-encoded extended spending key (169 bytes)."},
            {"rescan", RPCArg::Type::STR, RPCArg::Default{"whenkeyisnew"}, "\"yes\", \"no\", or \"whenkeyisnew\"."},
            {"startHeight", RPCArg::Type::NUM, RPCArg::Default{0}, "Block height to start rescanning from."},
        },
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{
            HelpExampleCli("z_importkey", "\"secret-spending-key-hex\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
            }

            std::string keyHex = request.params[0].get_str();
            auto keyBytes = ParseHex(keyHex);
            // Cleanse the hex string immediately after decoding
            memory_cleanse(keyHex.data(), keyHex.size());
            if (keyBytes.size() != 169) {
                memory_cleanse(keyBytes.data(), keyBytes.size());
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid key length: expected 169 bytes, got %d", keyBytes.size()));
            }

            sapling::SaplingExtendedSpendingKey sk;
            std::copy(keyBytes.begin(), keyBytes.end(), sk.key.begin());
            memory_cleanse(keyBytes.data(), keyBytes.size());

            std::string rescan = "whenkeyisnew";
            if (!request.params[1].isNull()) {
                rescan = request.params[1].get_str();
                if (rescan != "yes" && rescan != "no" && rescan != "whenkeyisnew") {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "Invalid rescan value. Must be \"yes\", \"no\", or \"whenkeyisnew\".");
                }
            }

            {
                LOCK(pwallet->cs_wallet);
                EnsureWalletIsUnlocked(*pwallet);

                auto& km = pwallet->GetSaplingKeyManager();

                bool keyExistedBefore = !km.IsEmpty();
                std::array<uint8_t, 32> ivk_bytes;
                try {
                    ivk_bytes = sapling::zip32::xsk_to_ivk(sk.key);
                } catch (const std::exception& e) {
                    memory_cleanse(sk.key.data(), sk.key.size());
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid spending key: %s", e.what()));
                }
                sapling::SaplingIncomingViewingKey checkIvk;
                checkIvk.key = ivk_bytes;
                bool isNew = !keyExistedBefore || !km.HaveIvk(checkIvk);

                // Capture master key for encrypted wallets: spending keys must be
                // encrypted before writing to DB when the wallet is encrypted.
                CKeyingMaterial masterKey;
                if (km.IsCrypto() && !pwallet->IsLocked()) {
                    pwallet->WithEncryptionKey([&](const CKeyingMaterial& vk) {
                        masterKey = vk;
                        return true;
                    });
                }
                const CKeyingMaterial* pMasterKey = masterKey.empty() ? nullptr : &masterKey;

                WalletBatch batch(pwallet->GetDatabase());
                if (!km.AddSpendingKeyWithDB(batch, sk, pMasterKey)) {
                    memory_cleanse(sk.key.data(), sk.key.size());
                    memory_cleanse(masterKey.data(), masterKey.size() * sizeof(CKeyingMaterial::value_type));
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to import Sapling spending key");
                }
                memory_cleanse(sk.key.data(), sk.key.size());
                memory_cleanse(masterKey.data(), masterKey.size() * sizeof(CKeyingMaterial::value_type));
                pwallet->SetMinVersion(FEATURE_SAPLING);
                if (rescan == "no" || (rescan == "whenkeyisnew" && !isNew)) {
                    return UniValue::VNULL;
                }
            }

            // Rescan blockchain for shielded notes (outside wallet lock to avoid deadlock)
            int nStartHeight = 0;
            if (!request.params[2].isNull()) {
                nStartHeight = request.params[2].getInt<int>();
                if (nStartHeight < 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "startHeight must be non-negative");
                }
            }

            std::optional<int> chainHeight = pwallet->chain().getHeight();
            if (chainHeight && nStartHeight > *chainHeight) {
                nStartHeight = *chainHeight;
            }

            WalletRescanReserver reserver(*pwallet);
            if (!reserver.reserve()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
            }

            LogPrintf("z_importkey: starting rescan from height %d\n", nStartHeight);

            CWallet::ScanResult result = pwallet->ScanForWalletTransactions(
                pwallet->chain().getBlockHash(nStartHeight),
                nStartHeight,
                /*max_height=*/std::nullopt,
                reserver,
                /*fUpdate=*/true,
                /*save_progress=*/true);

            if (result.status != CWallet::ScanResult::SUCCESS) {
                if (pwallet->IsAbortingRescan()) {
                    throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted by user.");
                } else {
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        "Rescan was unable to fully rescan the blockchain. "
                        "Some transactions may be missing.");
                }
            }

            LogPrintf("z_importkey: rescan complete\n");
            return UniValue::VNULL;
        },
    };
}

RPCHelpMan z_exportviewingkey()
{
    return RPCHelpMan{"z_exportviewingkey",
        "\nReveals the viewing key corresponding to a shielded address.\n"
        "The viewing key allows detecting incoming notes but cannot spend them.\n"
        "This is safe to share with auditors or watch-only wallets.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The shielded address."},
        },
        RPCResult{
            RPCResult::Type::STR, "key", "The hex-encoded viewing key (FVK 96 bytes + DK 32 bytes = 128 bytes)"
        },
        RPCExamples{
            HelpExampleCli("z_exportviewingkey", "\"ks1...\"")
            + HelpExampleRpc("z_exportviewingkey", "\"ks1...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(*pwallet);

            std::string addrStr = request.params[0].get_str();
            sapling::SaplingPaymentAddress addr;
            if (!DecodeSaplingAddress(addrStr, addr)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Sapling address");
            }

            const auto& km = pwallet->GetSaplingKeyManager();
            if (!km.HaveAddress(addr)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Address not found in wallet");
            }

            auto fvk = km.GetFvk(addr);
            if (!fvk) {
                throw JSONRPCError(RPC_WALLET_ERROR, "No viewing key available for this address");
            }

            auto dk = km.GetDk(addr);
            if (!dk) {
                throw JSONRPCError(RPC_WALLET_ERROR, "No diversifier key available for this address");
            }

            std::vector<uint8_t> vkData;
            vkData.reserve(128);
            vkData.insert(vkData.end(), fvk->ak.begin(), fvk->ak.end());
            vkData.insert(vkData.end(), fvk->nk.begin(), fvk->nk.end());
            vkData.insert(vkData.end(), fvk->ovk.begin(), fvk->ovk.end());
            vkData.insert(vkData.end(), dk->begin(), dk->end());

            std::string hexKey = HexStr(vkData);
            memory_cleanse(vkData.data(), vkData.size());
            UniValue ret(hexKey);
            memory_cleanse(hexKey.data(), hexKey.size());
            return ret;
        },
    };
}

RPCHelpMan z_importviewingkey()
{
    return RPCHelpMan{"z_importviewingkey",
        "\nImports a viewing key for watch-only tracking of a shielded address.\n"
        "The wallet will be able to detect incoming notes but cannot spend them.\n",
        {
            {"key", RPCArg::Type::STR, RPCArg::Optional::NO, "The hex-encoded viewing key (128 bytes: FVK 96 + DK 32)."},
            {"rescan", RPCArg::Type::STR, RPCArg::Default{"whenkeyisnew"}, "\"yes\", \"no\", or \"whenkeyisnew\"."},
            {"startHeight", RPCArg::Type::NUM, RPCArg::Default{0}, "Block height to start rescanning from."},
        },
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{
            HelpExampleCli("z_importviewingkey", "\"viewing-key-hex\"")
            + HelpExampleCli("z_importviewingkey", "\"viewing-key-hex\" \"no\"")
            + HelpExampleRpc("z_importviewingkey", "\"viewing-key-hex\", \"yes\", 1000")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            std::string keyHex = request.params[0].get_str();
            auto keyBytes = ParseHex(keyHex);
            if (keyBytes.size() != 128) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid viewing key length: expected 128 bytes (96 FVK + 32 DK), got %d", keyBytes.size()));
            }

            sapling::SaplingFullViewingKey fvk;
            std::copy(keyBytes.begin(),      keyBytes.begin() + 32, fvk.ak.begin());
            std::copy(keyBytes.begin() + 32, keyBytes.begin() + 64, fvk.nk.begin());
            std::copy(keyBytes.begin() + 64, keyBytes.begin() + 96, fvk.ovk.begin());

            std::array<uint8_t, 32> dk;
            std::copy(keyBytes.begin() + 96, keyBytes.begin() + 128, dk.begin());

            // Cleanse decoded key material
            memory_cleanse(keyHex.data(), keyHex.size());
            memory_cleanse(keyBytes.data(), keyBytes.size());

            std::array<uint8_t, 96> fvk_bytes;
            std::copy(fvk.ak.begin(), fvk.ak.end(), fvk_bytes.begin());
            std::copy(fvk.nk.begin(), fvk.nk.end(), fvk_bytes.begin() + 32);
            std::copy(fvk.ovk.begin(), fvk.ovk.end(), fvk_bytes.begin() + 64);
            std::array<uint8_t, 32> ivk_bytes;
            try {
                ivk_bytes = sapling::zip32::fvk_to_ivk(fvk_bytes);
            } catch (const std::exception& e) {
                memory_cleanse(fvk_bytes.data(), fvk_bytes.size());
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid viewing key: %s", e.what()));
            }
            memory_cleanse(fvk_bytes.data(), fvk_bytes.size());

            std::string rescan = "whenkeyisnew";
            if (!request.params[1].isNull()) {
                rescan = request.params[1].get_str();
                if (rescan != "yes" && rescan != "no" && rescan != "whenkeyisnew") {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "Invalid rescan value. Must be \"yes\", \"no\", or \"whenkeyisnew\".");
                }
            }

            {
                LOCK(pwallet->cs_wallet);

                auto& km = pwallet->GetSaplingKeyManager();

                sapling::SaplingIncomingViewingKey checkIvk;
                checkIvk.key = ivk_bytes;
                bool isNew = !km.HaveIvk(checkIvk);

                WalletBatch batch(pwallet->GetDatabase());
                if (!km.AddViewingKeyWithDB(batch, fvk, dk)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to import Sapling viewing key");
                }
                pwallet->SetMinVersion(FEATURE_SAPLING);

                if (rescan == "no" || (rescan == "whenkeyisnew" && !isNew)) {
                    return UniValue::VNULL;
                }
            }

            // Rescan blockchain for shielded notes (outside wallet lock to avoid deadlock)
            int nStartHeight = 0;
            if (!request.params[2].isNull()) {
                nStartHeight = request.params[2].getInt<int>();
                if (nStartHeight < 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "startHeight must be non-negative");
                }
            }

            std::optional<int> chainHeight = pwallet->chain().getHeight();
            if (chainHeight && nStartHeight > *chainHeight) {
                nStartHeight = *chainHeight;
            }

            WalletRescanReserver reserver(*pwallet);
            if (!reserver.reserve()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
            }

            LogPrintf("z_importviewingkey: starting rescan from height %d\n", nStartHeight);

            CWallet::ScanResult result = pwallet->ScanForWalletTransactions(
                pwallet->chain().getBlockHash(nStartHeight),
                nStartHeight,
                /*max_height=*/std::nullopt,
                reserver,
                /*fUpdate=*/true,
                /*save_progress=*/true);

            if (result.status != CWallet::ScanResult::SUCCESS) {
                if (pwallet->IsAbortingRescan()) {
                    throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted by user.");
                } else {
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        "Rescan was unable to fully rescan the blockchain. "
                        "Some transactions may be missing.");
                }
            }

            LogPrintf("z_importviewingkey: rescan complete\n");
            return UniValue::VNULL;
        },
    };
}

RPCHelpMan z_rebuildsaplingwitnesses()
{
    return RPCHelpMan{"z_rebuildsaplingwitnesses",
        "\nRebuild per-note Sapling incremental witnesses by replaying the block range\n"
        "covered by the wallet's unspent notes.\n"
        "Use when z_sendmany fails with anchor mismatch or corrupted-witness errors\n"
        "after a daemon stall, Sapling DB rebuild, or IBD re-catchup. Spent notes are\n"
        "not touched.\n",
        {
            {"from_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
             "Block height to start replay from. Defaults to the minimum blockHeight "
             "across all unspent notes."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "from_height", "Replay start height"},
                {RPCResult::Type::NUM, "to_height", "Chain tip height used for replay"},
                {RPCResult::Type::NUM, "blocks_processed", "Blocks replayed across the [from_height, to_height] range"},
                {RPCResult::Type::NUM, "notes_rebuilt", "Unspent notes whose witness was cleared and rebuilt"},
                {RPCResult::Type::ARR, "note_heights", "Per-note final state after replay",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "cmu", "Note commitment"},
                                {RPCResult::Type::NUM, "block_height", "Confirmed block height"},
                                {RPCResult::Type::NUM, "tree_position", "Merkle tree position (-1 if still missing)"},
                                {RPCResult::Type::BOOL, "has_witness", "Whether witness data was populated"},
                            }
                        },
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("z_rebuildsaplingwitnesses", "")
            + HelpExampleCli("z_rebuildsaplingwitnesses", "23795")
            + HelpExampleRpc("z_rebuildsaplingwitnesses", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // F5: concurrency guard. Reject if an auto-rebuild or another
            // RPC call is already in flight. Claim the slot atomically; a
            // scope guard releases it on every exit path.
            bool expected_active = false;
            if (!pwallet->m_sapling_rebuild_active.compare_exchange_strong(
                    expected_active, true, std::memory_order_acq_rel)) {
                throw JSONRPCError(RPC_IN_WARMUP,
                    "Sapling witness rebuild already in progress; wait for it to finish "
                    "(watch the debug log, or check getwalletinfo.sapling_rebuild_in_progress).");
            }
            struct ActiveGuard {
                std::atomic<bool>* flag;
                ~ActiveGuard() { if (flag) flag->store(false, std::memory_order_release); }
            } guard{&pwallet->m_sapling_rebuild_active};

            int tipHeight = -1;
            size_t notesRebuilt = 0;
            int noteMinHeight = std::numeric_limits<int>::max();
            int fromHeight = 0;

            // Phase A: preflight under cs_wallet. Nullifier derivation needs
            // the wallet unlocked; we also compute min(note.blockHeight) now,
            // before any state mutation, so the F1 invariant check is honest.
            {
                LOCK(pwallet->cs_wallet);
                EnsureWalletIsUnlocked(*pwallet);

                auto& km = pwallet->GetSaplingKeyManager();
                if (km.IsEmpty()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "No Sapling keys loaded");
                }

                tipHeight = pwallet->GetLastBlockHeight();
                if (tipHeight < 0) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Wallet has no tip height; finish sync first");
                }

                for (const auto& [cmu, nd] : km.GetAllNotes()) {
                    if (nd.isSpent || nd.blockHeight < 0) continue;
                    ++notesRebuilt;
                    if (nd.blockHeight < noteMinHeight) noteMinHeight = nd.blockHeight;
                }
                if (notesRebuilt == 0) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "No unspent confirmed Sapling notes to rebuild");
                }
                if (noteMinHeight == std::numeric_limits<int>::max()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Could not determine minimum note height");
                }

                // F1: enforce the from_height invariant. Prior behaviour
                // cleared witnesses for all unspent notes unconditionally,
                // then replayed from from_height. Any note with
                // blockHeight < from_height was cleared on disk but never
                // rebuilt, silently leaving it permanently unspendable.
                // Refuse the call so the operator can re-invoke with a safe
                // start height.
                if (!request.params[0].isNull()) {
                    fromHeight = request.params[0].getInt<int>();
                    if (fromHeight < 0) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "from_height must be non-negative");
                    }
                    if (fromHeight > noteMinHeight) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("from_height %d is greater than the minimum unspent-note "
                                      "height %d. Rebuilding from a later height would clear "
                                      "witnesses for earlier notes without replaying their "
                                      "commitments, silently leaving them unspendable. Either "
                                      "omit from_height (defaults to %d) or pass a value <= %d.",
                                      fromHeight, noteMinHeight, noteMinHeight, noteMinHeight));
                    }
                } else {
                    fromHeight = noteMinHeight;
                }
                if (fromHeight > tipHeight) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("from_height %d exceeds chain tip %d", fromHeight, tipHeight));
                }
            } // release cs_wallet before the chunked replay

            LogPrintf("z_rebuildsaplingwitnesses: replaying blocks %d..%d for %u notes "
                      "(min note height=%d)\n",
                      fromHeight, tipHeight, (unsigned)notesRebuilt, noteMinHeight);

            // Phase B: delegate to CWallet. The synchronous helper persists
            // the crash-safety marker, clears witness data, captures a chain
            // snapshot, runs the chunked replay (re-acquiring cs_wallet per
            // chunk), and clears the marker on success.
            int blocksProcessed = pwallet->RebuildSaplingWitnessesSynchronous(fromHeight);
            if (blocksProcessed < 0) {
                throw JSONRPCError(RPC_MISC_ERROR,
                    "Witness rebuild aborted: shutdown requested, chain reorged during replay, "
                    "or block data unavailable (pruned node?). See log for the specific failing "
                    "height. The persistent in-progress marker has been retained; the next "
                    "wallet load (or the next block tip) will retry automatically. Restart "
                    "kerrigand with -reindex or -reindex-chainstate if block data was pruned.");
            }

            // Phase C: build response under cs_wallet.
            UniValue result(UniValue::VOBJ);
            result.pushKV("from_height", fromHeight);
            result.pushKV("to_height", tipHeight);
            result.pushKV("blocks_processed", blocksProcessed);
            result.pushKV("notes_rebuilt", (int)notesRebuilt);

            UniValue heights(UniValue::VARR);
            {
                LOCK(pwallet->cs_wallet);
                auto& km = pwallet->GetSaplingKeyManager();
                for (const auto& [cmu, nd] : km.GetAllNotes()) {
                    if (nd.isSpent || nd.blockHeight < 0) continue;
                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("cmu", cmu.GetHex());
                    entry.pushKV("block_height", nd.blockHeight);
                    entry.pushKV("tree_position", nd.treePosition);
                    entry.pushKV("has_witness", !nd.witnessData.empty());
                    heights.push_back(entry);
                }
            }
            result.pushKV("note_heights", heights);

            LogPrintf("z_rebuildsaplingwitnesses: complete, %d blocks replayed\n", blocksProcessed);
            return result;
        },
    };
}

} // namespace wallet
