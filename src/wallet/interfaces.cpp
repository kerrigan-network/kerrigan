// Copyright (c) 2018-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/wallet.h>

#include <chain.h>
#include <consensus/amount.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <interfaces/chain.h>
#include <interfaces/handler.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <script/standard.h>
#include <support/allocators/secure.h>
#include <sync.h>
#include <uint256.h>
#include <util/check.h>
#include <util/system.h>
#include <util/translation.h>
#include <util/ui_change_type.h>
#include <validation.h>
#include <chainparams.h>
#include <key_io.h>
#include <rust/bridge.h>
#include <sapling/sapling_init.h>
#include <sapling/sapling_transaction_builder.h>
#include <sapling/sapling_tx_payload.h>
#include <random.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/fees.h>
#include <wallet/ismine.h>
#include <wallet/load.h>
#include <wallet/receive.h>
#include <wallet/rpc/wallet.h>
#include <wallet/sapling_keymanager.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/hdchain.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/walletutil.h>
#include <governance/validators.h>
#include <evo/deterministicmns.h>
#include <masternode/sync.h>
#include <txdb.h>
#include <node/context.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

using interfaces::Chain;
using interfaces::FoundBlock;
using interfaces::Handler;
using interfaces::MakeHandler;
using interfaces::Wallet;
using interfaces::WalletAddress;
using interfaces::WalletBalances;
using interfaces::WalletLoader;
using interfaces::WalletOrderForm;
using interfaces::WalletTx;
using interfaces::WalletTxOut;
using interfaces::WalletTxStatus;
using interfaces::WalletValueMap;
using node::NodeContext;

namespace wallet {
namespace {
//! Construct wallet tx struct.
WalletTx MakeWalletTx(CWallet& wallet, const CWalletTx& wtx)
{
    LOCK(wallet.cs_wallet);
    WalletTx result;
    result.tx = wtx.tx;
    result.txin_is_mine.reserve(wtx.tx->vin.size());
    for (const auto& txin : wtx.tx->vin) {
        result.txin_is_mine.emplace_back(InputIsMine(wallet, txin));
    }
    result.txout_is_mine.reserve(wtx.tx->vout.size());
    result.txout_address.reserve(wtx.tx->vout.size());
    result.txout_address_is_mine.reserve(wtx.tx->vout.size());
    for (const auto& txout : wtx.tx->vout) {
        result.txout_is_mine.emplace_back(wallet.IsMine(txout));
        result.txout_address.emplace_back();
        result.txout_address_is_mine.emplace_back(ExtractDestination(txout.scriptPubKey, result.txout_address.back()) ?
                                                      wallet.IsMine(result.txout_address.back()) :
                                                      ISMINE_NO);
    }
    result.credit = CachedTxGetCredit(wallet, wtx, ISMINE_ALL);
    result.debit = CachedTxGetDebit(wallet, wtx, ISMINE_ALL);
    result.change = CachedTxGetChange(wallet, wtx);
    result.time = wtx.GetTxTime();
    result.value_map = wtx.mapValue;
    result.is_coinbase = wtx.IsCoinBase();
    result.is_platform_transfer = wtx.IsPlatformTransfer();
    return result;
}

//! Construct wallet tx status struct.
WalletTxStatus MakeWalletTxStatus(const CWallet& wallet, const CWalletTx& wtx)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    WalletTxStatus result;
    result.block_height =
        wtx.state<TxStateConfirmed>() ? wtx.state<TxStateConfirmed>()->confirmed_block_height :
        wtx.state<TxStateConflicted>() ? wtx.state<TxStateConflicted>()->conflicting_block_height :
        std::numeric_limits<int>::max();
    result.blocks_to_maturity = wallet.GetTxBlocksToMaturity(wtx);
    result.depth_in_main_chain = wallet.GetTxDepthInMainChain(wtx);
    result.time_received = wtx.nTimeReceived;
    result.lock_time = wtx.tx->nLockTime;
    result.is_trusted = CachedTxIsTrusted(wallet, wtx);
    result.is_abandoned = wtx.isAbandoned();
    result.is_coinbase = wtx.IsCoinBase();
    result.is_in_main_chain = wallet.IsTxInMainChain(wtx);
    result.is_chainlocked = wallet.IsTxChainLocked(wtx);
    result.is_islocked = wallet.IsTxLockedByInstantSend(wtx);
    return result;
}

//! Construct wallet TxOut struct.
WalletTxOut MakeWalletTxOut(const CWallet& wallet,
    const CWalletTx& wtx,
    int n,
    int depth) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    WalletTxOut result;
    result.txout = wtx.tx->vout[n];
    result.time = wtx.GetTxTime();
    result.depth_in_main_chain = depth;
    result.is_spent = wallet.IsSpent(COutPoint(wtx.GetHash(), n));
    return result;
}

WalletTxOut MakeWalletTxOut(const CWallet& wallet,
    const COutput& output) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    WalletTxOut result;
    result.txout = output.txout;
    result.time = output.time;
    result.depth_in_main_chain = output.depth;
    result.is_spent = wallet.IsSpent(output.outpoint);
    return result;
}

class WalletImpl : public Wallet
{
public:
    explicit WalletImpl(WalletContext& context, const std::shared_ptr<CWallet>& wallet) : m_context(context), m_wallet(wallet) {}

    void markDirty() override
    {
        m_wallet->MarkDirty();
    }
    bool encryptWallet(const SecureString& wallet_passphrase) override
    {
        return m_wallet->EncryptWallet(wallet_passphrase);
    }
    bool isCrypted() override { return m_wallet->IsCrypted(); }
    bool lock() override { return m_wallet->Lock(); }
    bool unlock(const SecureString& wallet_passphrase) override { return m_wallet->Unlock(wallet_passphrase); }
    bool isLocked() override { return m_wallet->IsLocked(); }
    bool changeWalletPassphrase(const SecureString& old_wallet_passphrase,
        const SecureString& new_wallet_passphrase) override
    {
        return m_wallet->ChangeWalletPassphrase(old_wallet_passphrase, new_wallet_passphrase);
    }
    wallet::RescanStatus startRescan(bool from_genesis) override
    {
        int rescan_height{0};
        if (!from_genesis) {
            std::optional<int64_t> time_first_key;
            for (auto spk_man : m_wallet->GetAllScriptPubKeyMans()) {
                int64_t time = spk_man->GetTimeFirstKey();
                if (!time_first_key || time < *time_first_key) time_first_key = time;
            }
            if (time_first_key) {
                m_wallet->chain().findFirstBlockWithTimeAndHeight(*time_first_key - TIMESTAMP_WINDOW, rescan_height,
                                                                  FoundBlock().height(rescan_height));
            }
        }

        WalletRescanReserver reserver(*m_wallet);
        if (!reserver.reserve()) {
            return wallet::RescanStatus::BUSY;
        }
        switch (m_wallet->ScanForWalletTransactions(m_wallet->chain().getBlockHash(rescan_height), rescan_height, /*max_height=*/std::nullopt,
                                                    reserver, /*fUpdate=*/true, /*save_progress=*/false).status) {
        case CWallet::ScanResult::FAILURE:
            return wallet::RescanStatus::FAILURE;
        case CWallet::ScanResult::SUCCESS:
            return wallet::RescanStatus::SUCCESS;
        case CWallet::ScanResult::USER_ABORT:
            return wallet::RescanStatus::USER_ABORT;
        }
        Assume(false); // unreachable
        return wallet::RescanStatus::FAILURE; // fallback for release builds
    }
    void abortRescan() override { m_wallet->AbortRescan(); }
    void autoLockMasternodeCollaterals() override { m_wallet->AutoLockMasternodeCollaterals(); }
    bool backupWallet(const std::string& filename) override { return m_wallet->BackupWallet(filename); }
    bool autoBackupWallet(const fs::path& wallet_path, bilingual_str& error_string, std::vector<bilingual_str>& warnings) override
    {
        return m_wallet->AutoBackupWallet(wallet_path, error_string, warnings);
    }
    int64_t getKeysLeftSinceAutoBackup() override { return m_wallet->nKeysLeftSinceAutoBackup; }
    std::string getWalletName() override { return m_wallet->GetName(); }
    util::Result<CTxDestination> getNewDestination(const std::string& label) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetNewDestination(label);
    }
    bool getPubKey(const CScript& script, const CKeyID& address, CPubKey& pub_key) override
    {
        std::unique_ptr<SigningProvider> provider = m_wallet->GetSolvingProvider(script);
        if (provider) {
            return provider->GetPubKey(address, pub_key);
        }
        return false;
    }
    SigningResult signMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) override
    {
        return m_wallet->SignMessage(message, pkhash, str_sig);
    }
    bool signSpecialTxPayload(const uint256& hash, const CKeyID& keyid, std::vector<unsigned char>& vchSig) override
    {
        return m_wallet->SignSpecialTxPayload(hash, keyid, vchSig);
    }
    bool isSpendable(const CScript& script) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsMine(script) & ISMINE_SPENDABLE;
    }
    bool isSpendable(const CTxDestination& dest) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsMine(dest) & ISMINE_SPENDABLE;
    }
    bool haveWatchOnly() override
    {
        auto spk_man = m_wallet->GetLegacyScriptPubKeyMan();
        if (spk_man) {
            return spk_man->HaveWatchOnly();
        }
        return false;
    };
    bool setAddressBook(const CTxDestination& dest, const std::string& name, const std::string& purpose) override
    {
        return m_wallet->SetAddressBook(dest, name, purpose);
    }
    bool delAddressBook(const CTxDestination& dest) override
    {
        return m_wallet->DelAddressBook(dest);
    }
    bool getAddress(const CTxDestination& dest,
        std::string* name,
        wallet::isminetype* is_mine,
        std::string* purpose) override
    {
        LOCK(m_wallet->cs_wallet);
        const auto& entry = m_wallet->FindAddressBookEntry(dest, /*allow_change=*/false);
        if (!entry) return false; // addr not found
        if (name) {
            *name = entry->GetLabel();
        }
        if (is_mine) {
            *is_mine = m_wallet->IsMine(dest);
        }
        if (purpose) {
            *purpose = entry->purpose;
        }
        return true;
    }
    std::vector<WalletAddress> getAddresses() const override
    {
        LOCK(m_wallet->cs_wallet);
        std::vector<WalletAddress> result;
        m_wallet->ForEachAddrBookEntry([&](const CTxDestination& dest, const std::string& label, const std::string& purpose, bool is_change) EXCLUSIVE_LOCKS_REQUIRED(m_wallet->cs_wallet) {
            if (is_change) return;
            result.emplace_back(dest, m_wallet->IsMine(dest), label, purpose);
        });
        return result;
    }
    std::vector<std::string> getAddressReceiveRequests() override {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetAddressReceiveRequests();
    }
    bool setAddressReceiveRequest(const CTxDestination& dest, const std::string& id, const std::string& value) override {
        LOCK(m_wallet->cs_wallet);
        WalletBatch batch{m_wallet->GetDatabase()};
        return m_wallet->SetAddressReceiveRequest(batch, dest, id, value);
    }
    bool displayAddress(const CTxDestination& dest) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->DisplayAddress(dest);
    }
    bool lockCoin(const COutPoint& output, const bool write_to_db) override
    {
        LOCK(m_wallet->cs_wallet);
        std::unique_ptr<WalletBatch> batch = write_to_db ? std::make_unique<WalletBatch>(m_wallet->GetDatabase()) : nullptr;
        return m_wallet->LockCoin(output, batch.get());
    }
    bool unlockCoin(const COutPoint& output) override
    {
        LOCK(m_wallet->cs_wallet);
        std::unique_ptr<WalletBatch> batch = std::make_unique<WalletBatch>(m_wallet->GetDatabase());
        return m_wallet->UnlockCoin(output, batch.get());
    }
    bool isLockedCoin(const COutPoint& output) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsLockedCoin(output);
    }
    std::vector<COutPoint> listLockedCoins() override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->ListLockedCoins();
    }
    std::vector<COutPoint> listProTxCoins() override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->ListProTxCoins();
    }
    util::Result<CTransactionRef> createTransaction(const std::vector<CRecipient>& recipients,
        const CCoinControl& coin_control,
        bool sign,
        int& change_pos,
        CAmount& fee) override
    {
        LOCK(m_wallet->cs_wallet);
        auto res = CreateTransaction(*m_wallet, recipients, change_pos, coin_control, sign);
        if (!res) return util::Error{util::ErrorString(res)};
        const auto& txr = *res;
        fee = txr.fee;
        change_pos = txr.change_pos;

        return txr.tx;
    }
    void commitTransaction(CTransactionRef tx,
        WalletValueMap value_map,
        WalletOrderForm order_form) override
    {
        LOCK(m_wallet->cs_wallet);
        m_wallet->CommitTransaction(std::move(tx), std::move(value_map), std::move(order_form));
    }
    bool transactionCanBeAbandoned(const uint256& txid) override { return m_wallet->TransactionCanBeAbandoned(txid); }
    bool transactionCanBeResent(const uint256& txid) override { return m_wallet->TransactionCanBeResent(txid); }
    bool abandonTransaction(const uint256& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->AbandonTransaction(txid);
    }
    bool resendTransaction(const uint256& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->ResendTransaction(txid);
    }
    CTransactionRef getTx(const uint256& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi != m_wallet->mapWallet.end()) {
            return mi->second.tx;
        }
        return {};
    }
    WalletTx getWalletTx(const uint256& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi != m_wallet->mapWallet.end()) {
            return MakeWalletTx(*m_wallet, mi->second);
        }
        return {};
    }
    std::set<WalletTx> getWalletTxs() override
    {
        LOCK(m_wallet->cs_wallet);
        std::set<WalletTx> result;
        for (const auto& entry : m_wallet->mapWallet) {
            result.emplace(MakeWalletTx(*m_wallet, entry.second));
        }
        return result;
    }
    bool tryGetTxStatus(const uint256& txid,
        interfaces::WalletTxStatus& tx_status,
        int& num_blocks,
        int64_t& block_time) override
    {
        TRY_LOCK(m_wallet->cs_wallet, locked_wallet);
        if (!locked_wallet) {
            return false;
        }
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi == m_wallet->mapWallet.end()) {
            return false;
        }
        num_blocks = m_wallet->GetLastBlockHeight();
        block_time = -1;
        CHECK_NONFATAL(m_wallet->chain().findBlock(m_wallet->GetLastBlockHash(), FoundBlock().time(block_time)));
        tx_status = MakeWalletTxStatus(*m_wallet, mi->second);
        return true;
    }
    WalletTx getWalletTxDetails(const uint256& txid,
        WalletTxStatus& tx_status,
        WalletOrderForm& order_form,
        bool& in_mempool,
        int& num_blocks) override
    {
        LOCK(m_wallet->cs_wallet);
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi != m_wallet->mapWallet.end()) {
            num_blocks = m_wallet->GetLastBlockHeight();
            in_mempool = mi->second.InMempool();
            order_form = mi->second.vOrderForm;
            tx_status = MakeWalletTxStatus(*m_wallet, mi->second);
            return MakeWalletTx(*m_wallet, mi->second);
        }
        return {};
    }
    TransactionError fillPSBT(int sighash_type,
        bool sign,
        bool bip32derivs,
        size_t* n_signed,
        PartiallySignedTransaction& psbtx,
        bool& complete) override
    {
        return m_wallet->FillPSBT(psbtx, complete, sighash_type, sign, bip32derivs, n_signed);
    }
    WalletBalances getBalances() override
    {
        const auto bal = GetBalance(*m_wallet);
        WalletBalances result;
        result.balance = bal.m_mine_trusted;
        result.unconfirmed_balance = bal.m_mine_untrusted_pending;
        result.immature_balance = bal.m_mine_immature;
        result.have_watch_only = haveWatchOnly();
        if (result.have_watch_only) {
            result.watch_only_balance = bal.m_watchonly_trusted;
            result.unconfirmed_watch_only_balance = bal.m_watchonly_untrusted_pending;
            result.immature_watch_only_balance = bal.m_watchonly_immature;
        }
        result.shielded_balance = m_wallet->GetSaplingKeyManager().GetSaplingBalance();
        return result;
    }
    bool tryGetBalances(WalletBalances& balances, uint256& block_hash) override
    {
        TRY_LOCK(m_wallet->cs_wallet, locked_wallet);
        if (!locked_wallet) {
            return false;
        }
        block_hash = m_wallet->GetLastBlockHash();
        balances = getBalances();
        return true;
    }
    CAmount getBalance() override { return GetBalance(*m_wallet).m_mine_trusted; }
    CAmount getAvailableBalance(const CCoinControl& coin_control) override
    {
        return GetAvailableBalance(*m_wallet, &coin_control);
    }
    CAmount getShieldedBalance() override
    {
        return m_wallet->GetSaplingKeyManager().GetSaplingBalance();
    }
    std::string getNewSaplingAddress() override
    {
        LOCK(m_wallet->cs_wallet);
        if (m_wallet->IsLocked()) {
            throw std::runtime_error("Wallet is locked. Unlock it first.");
        }
        auto& km = m_wallet->GetSaplingKeyManager();

        // If no Sapling key exists yet, derive master spending key (same as z_getnewaddress RPC)
        if (km.IsEmpty()) {
            SecureVector seed;

            // Try legacy wallet HD seed first, fall back to random seed
            LegacyScriptPubKeyMan* spk_man = m_wallet->GetLegacyScriptPubKeyMan();
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
            std::array<uint8_t, 169> xsk_bytes;
            try {
                xsk_bytes = ::sapling::zip32::xsk_master(seed_slice);
                xsk_bytes = ::sapling::zip32::xsk_derive(xsk_bytes, 32 | 0x80000000);
                xsk_bytes = ::sapling::zip32::xsk_derive(xsk_bytes, uint32_t(Params().ExtCoinType()) | 0x80000000);
                xsk_bytes = ::sapling::zip32::xsk_derive(xsk_bytes, 0 | 0x80000000);
            } catch (const std::exception& e) {
                throw std::runtime_error(strprintf("Failed to derive Sapling spending key: %s", e.what()));
            }

            sapling::SaplingExtendedSpendingKey sk;
            sk.key = xsk_bytes;
            memory_cleanse(xsk_bytes.data(), xsk_bytes.size());

            CKeyingMaterial masterKey;
            if (km.IsCrypto() && !m_wallet->IsLocked()) {
                m_wallet->WithEncryptionKey([&](const CKeyingMaterial& vk) {
                    masterKey = vk;
                    return true;
                });
            }
            const CKeyingMaterial* pMasterKey = masterKey.empty() ? nullptr : &masterKey;

            WalletBatch batch(m_wallet->GetDatabase());
            if (!km.AddSpendingKeyWithDB(batch, sk, pMasterKey)) {
                memory_cleanse(sk.key.data(), sk.key.size());
                memory_cleanse(masterKey.data(), masterKey.size() * sizeof(CKeyingMaterial::value_type));
                throw std::runtime_error("Failed to add Sapling spending key");
            }
            memory_cleanse(sk.key.data(), sk.key.size());
            memory_cleanse(masterKey.data(), masterKey.size() * sizeof(CKeyingMaterial::value_type));
            m_wallet->SetMinVersion(FEATURE_SAPLING);
        }

        auto addr = km.GenerateNewAddress();
        if (!addr) {
            throw std::runtime_error("Failed to generate Sapling address");
        }
        WalletBatch batch(m_wallet->GetDatabase());
        km.WriteAddressToDB(batch, *addr);
        km.WriteDiversifierIndexToDB(batch);
        return EncodeSaplingAddress(*addr);
    }
    std::vector<std::string> listSaplingAddresses() override
    {
        const auto& km = m_wallet->GetSaplingKeyManager();
        auto addresses = km.GetAllAddresses();
        std::vector<std::string> result;
        result.reserve(addresses.size());
        for (const auto& addr : addresses) {
            result.push_back(EncodeSaplingAddress(addr));
        }
        return result;
    }
    std::vector<ShieldedNoteInfo> getShieldedNoteHistory() override
    {
        const auto& km = m_wallet->GetSaplingKeyManager();
        auto allNotes = km.GetAllNotes();
        std::vector<ShieldedNoteInfo> result;
        result.reserve(allNotes.size());
        for (const auto& [cmu, nd] : allNotes) {
            ShieldedNoteInfo info;
            info.cmu = cmu;
            info.value = nd.value;
            info.address = EncodeSaplingAddress(nd.recipient);
            // Decode memo: extract printable ASCII prefix
            std::string memo;
            for (size_t i = 0; i < nd.memo.size(); ++i) {
                uint8_t c = nd.memo[i];
                if (c == 0) break;
                if (c >= 32 && c < 127) memo += static_cast<char>(c);
            }
            info.memo = memo;
            info.txid = nd.txid;
            info.outputIndex = nd.outputIndex;
            info.blockHeight = nd.blockHeight;
            info.isSpent = nd.isSpent;
            info.spendingTxid = nd.spendingTxid;
            result.push_back(std::move(info));
        }
        return result;
    }
    std::string saplingZSendMany(const std::string& from_address,
        const std::vector<std::pair<std::string, CAmount>>& recipients,
        int minconf,
        std::optional<CAmount> fee) override
    {
        WAIT_LOCK(m_wallet->cs_wallet, wallet_lock);

        // Check wallet is unlocked early, before expensive proof generation
        if (m_wallet->IsLocked()) {
            throw std::runtime_error("Wallet is locked");
        }

        if (!sapling::IsSaplingInitialized()) {
            throw std::runtime_error("Sapling parameters not loaded");
        }

        auto& km = m_wallet->GetSaplingKeyManager();

        // Parse source address
        sapling::SaplingPaymentAddress fromSapling;
        bool fromIsShielded = DecodeSaplingAddress(from_address, fromSapling);
        CTxDestination fromTransparent;
        if (!fromIsShielded) {
            fromTransparent = DecodeDestination(from_address);
            if (!IsValidDestination(fromTransparent)) {
                throw std::runtime_error("Invalid from address");
            }
        }

        // #747: Reject empty recipient list (matches RPC path)
        if (recipients.empty()) {
            throw std::runtime_error("No recipients specified");
        }
        // #748: Reject negative minconf (matches RPC path)
        if (minconf < 0) {
            throw std::runtime_error("minconf must be non-negative");
        }

        // Parse recipients
        struct Recipient {
            bool isShielded;
            sapling::SaplingPaymentAddress saplingAddr;
            CTxDestination transparentDest;
            CAmount amount;
        };
        std::vector<Recipient> parsedRecipients;
        CAmount totalSend = 0;
        size_t nShieldedOutputs = 0;

        for (const auto& [addrStr, amount] : recipients) {
            Recipient r;
            r.amount = amount;
            // #745: Validate per-recipient amount (matches RPC path)
            if (r.amount <= 0 || !MoneyRange(r.amount)) {
                throw std::runtime_error("Invalid recipient amount");
            }
            r.isShielded = DecodeSaplingAddress(addrStr, r.saplingAddr);
            if (!r.isShielded) {
                r.transparentDest = DecodeDestination(addrStr);
                if (!IsValidDestination(r.transparentDest)) {
                    throw std::runtime_error("Invalid recipient address: " + addrStr);
                }
            } else {
                nShieldedOutputs++;
            }
            // #711: Overflow guard (matches RPC path)
            if (r.amount > MAX_MONEY - totalSend) {
                throw std::runtime_error("Total send amount out of range");
            }
            totalSend += r.amount;
            parsedRecipients.push_back(std::move(r));
        }

        bool hasShielded = fromIsShielded || nShieldedOutputs > 0;
        if (!hasShielded) {
            throw std::runtime_error("z_sendmany requires at least one shielded address");
        }

        const auto& chainparams = Params();
        const auto& params = chainparams.GetConsensus();
        int tipHeight = m_wallet->GetLastBlockHeight();
        std::string netID = chainparams.NetworkIDString();

        // Get anchor
        std::array<uint8_t, 32> anchor{};
        {
            uint256 anchorHash;
            if (sapling::GetBestAnchor(tipHeight, anchorHash)) {
                std::copy(anchorHash.begin(), anchorHash.end(), anchor.begin());
            }
        }

        SaplingTransactionBuilder builder(params, tipHeight + 1, anchor, netID);

        CAmount txFee = fee.value_or(SAPLING_BASE_FEE);
        // #749/#777: Validate explicit fee is positive and within range
        if (fee.has_value() && (!MoneyRange(txFee) || txFee <= 0)) {
            throw std::runtime_error("Fee must be positive");
        }
        size_t nShieldedSpends = 0;
        std::set<uint256> selectedNullifiers; // #653: track selected notes for reservation
        std::vector<COutPoint> lockedCoins; // #1022: track locked UTXOs for cleanup

        if (fromIsShielded) {
            if (!km.CanSpend(fromSapling)) {
                throw std::runtime_error("Don't have spending key for source address");
            }
            auto sk = km.GetSpendingKey(fromSapling);
            if (!sk) {
                throw std::runtime_error("Spending key not found");
            }

            auto allNotes = km.GetUnspentNotes(fromSapling);
            std::vector<SaplingNoteData> notes;
            for (const auto& note : allNotes) {
                int confs = (note.blockHeight >= 0) ? (tipHeight - note.blockHeight + 1) : 0;
                if (confs >= minconf) {
                    notes.push_back(note);
                }
            }

            // Fee estimation: convergence loop handles the circular
            // dependency between spend count, change output, and fee.
            if (!fee.has_value()) {
                CAmount prevFee = -1;
                // Apply 2-output privacy padding (matches RPC path)
                CAmount estimatedFee = CalculateSaplingFee(1, std::max(size_t{2}, nShieldedOutputs));
                for (int iter = 0; iter < 10 && estimatedFee != prevFee; ++iter) {
                    prevFee = estimatedFee;

                    CAmount runningTotal = 0;
                    size_t estimatedSpends = 0;
                    for (const auto& note : notes) {
                        if (runningTotal >= totalSend + estimatedFee) break;
                        estimatedSpends++;
                        runningTotal += note.value;
                    }
                    if (estimatedSpends == 0) estimatedSpends = 1;

                    bool hasChange = (runningTotal > totalSend + estimatedFee);
                    size_t totalOutputs = std::max(size_t{2}, nShieldedOutputs + (hasChange ? 1 : 0));
                    estimatedFee = CalculateSaplingFee(estimatedSpends, totalOutputs);
                }
                txFee = estimatedFee;
            }

            // Select notes
            CAmount noteTotal = 0;
            for (const auto& note : notes) {
                if (noteTotal >= totalSend + txFee) break;
                nShieldedSpends++;

                if (note.witnessData.empty()) {
                    throw std::runtime_error("Note has no Merkle witness");
                }
                std::array<uint8_t, 1065> merklePathArr;
                try {
                    rust::Slice<const uint8_t> witSlice(note.witnessData.data(), note.witnessData.size());
                    auto witness = sapling::tree::witness_deserialize(witSlice);
                    auto merklePath = sapling::tree::witness_path(*witness);
                    if (merklePath.size() != 1065) {
                        throw std::runtime_error("unexpected Merkle path size");
                    }
                    std::copy(merklePath.begin(), merklePath.end(), merklePathArr.begin());
                } catch (const rust::Error& e) {
                    throw std::runtime_error(strprintf("Corrupt Merkle witness for note in tx %s: %s", note.txid.GetHex(), e.what()));
                }

                std::array<uint8_t, 43> recipientArr;
                std::copy(note.recipient.d.begin(), note.recipient.d.end(), recipientArr.begin());
                std::copy(note.recipient.pk_d.begin(), note.recipient.pk_d.end(), recipientArr.begin() + 11);

                if (!builder.AddSaplingSpend(*sk, recipientArr, note.value, note.rseed, merklePathArr)) {
                    throw std::runtime_error("Failed to add Sapling spend");
                }
                noteTotal += note.value;
                // Skip notes with null nullifiers
                if (!note.nullifier.IsNull()) {
                    selectedNullifiers.insert(note.nullifier);
                }
            }

            if (noteTotal < totalSend + txFee) {
                throw std::runtime_error("Insufficient shielded funds");
            }

            // Reserve selected notes to prevent double-selection during unlock
            if (!selectedNullifiers.empty()) {
                km.ReserveNotesByNullifier(selectedNullifiers);
            }

            // Change output
            CAmount change = noteTotal - totalSend - txFee;
            if (change > 0) {
                auto fvk = km.GetFvk(fromSapling);
                auto dk = km.GetDk(fromSapling);
                if (!fvk || !dk) {
                    // #742: Unreserve notes before throwing
                    if (!selectedNullifiers.empty()) km.UnreserveNotesByNullifier(selectedNullifiers);
                    throw std::runtime_error("Cannot derive change address");
                }

                std::array<uint8_t, 96> fvk_bytes;
                std::copy(fvk->ak.begin(), fvk->ak.end(), fvk_bytes.begin());
                std::copy(fvk->nk.begin(), fvk->nk.end(), fvk_bytes.begin() + 32);
                std::copy(fvk->ovk.begin(), fvk->ovk.end(), fvk_bytes.begin() + 64);

                // #861: Wrap derivation in try-catch to unreserve notes on failure
                decltype(sapling::zip32::derive_internal_fvk(fvk_bytes, *dk)) internalFvk;
                decltype(sapling::zip32::find_address(internalFvk.fvk, internalFvk.dk, std::array<uint8_t, 11>{})) internalAddr;
                try {
                    internalFvk = sapling::zip32::derive_internal_fvk(fvk_bytes, *dk);
                    std::array<uint8_t, 11> j_start{};
                    GetStrongRandBytes(Span{j_start.data(), 8});
                    internalAddr = sapling::zip32::find_address(internalFvk.fvk, internalFvk.dk, j_start);
                } catch (...) {
                    if (!selectedNullifiers.empty()) km.UnreserveNotesByNullifier(selectedNullifiers);
                    throw;
                }

                std::array<uint8_t, 32> changeOvk;
                std::copy(internalFvk.fvk.begin() + 64, internalFvk.fvk.begin() + 96, changeOvk.begin());

                if (!builder.AddSaplingOutput(changeOvk, internalAddr.addr, change)) {
                    // #742: Unreserve notes before throwing
                    if (!selectedNullifiers.empty()) km.UnreserveNotesByNullifier(selectedNullifiers);
                    throw std::runtime_error("Failed to add shielded change output");
                }
            }
        } else {
            // Transparent source
            if (!fee.has_value()) {
                // #741: Apply 2-output privacy padding (matches RPC + shielded-source path)
                txFee = CalculateSaplingFee(0, std::max(size_t{2}, nShieldedOutputs));
            }

            CCoinControl coin_control;
            coin_control.m_min_depth = minconf;

            // Use AvailableCoinsListUnspent to include spendable descriptor-wallet UTXOs
            CoinsResult available_coins = AvailableCoinsListUnspent(*m_wallet, &coin_control);
            auto allCoins = available_coins.all();

            CScript sourceScript = GetScriptForDestination(fromTransparent);
            allCoins.erase(
                std::remove_if(allCoins.begin(), allCoins.end(),
                    [&sourceScript](const COutput& c) {
                        return c.txout.scriptPubKey != sourceScript;
                    }),
                allCoins.end());

            CAmount sourceTotal = 0;
            for (const auto& coin : allCoins) {
                // #744: MoneyRange overflow guard (matches RPC path)
                if (!MoneyRange(sourceTotal + coin.txout.nValue)) {
                    throw std::runtime_error("Transparent balance overflow");
                }
                sourceTotal += coin.txout.nValue;
            }

            if (sourceTotal < totalSend + txFee) {
                throw std::runtime_error("Insufficient transparent funds");
            }

            std::sort(allCoins.begin(), allCoins.end(), [](const COutput& a, const COutput& b) {
                return a.txout.nValue > b.txout.nValue;
            });

            CAmount transparentTotal = 0;
            for (const auto& coin : allCoins) {
                if (transparentTotal >= totalSend + txFee) break;
                builder.AddTransparentInput(coin.outpoint, coin.txout.scriptPubKey, coin.txout.nValue);
                m_wallet->LockCoin(coin.outpoint);
                lockedCoins.push_back(coin.outpoint);
                transparentTotal += coin.txout.nValue;
            }

            CAmount change = transparentTotal - totalSend - txFee;
            CScript scriptChange = GetScriptForDestination(fromTransparent);
            CTxOut changeTxOut(change, scriptChange);
            if (change > 0 && !IsDust(changeTxOut, m_wallet->chain().relayDustFee())) {
                builder.AddTransparentOutput(scriptChange, change);
            } else if (change > 0) {
                txFee += change;
            }
        }

        // Add recipients
        for (const auto& r : parsedRecipients) {
            if (r.isShielded) {
                std::array<uint8_t, 43> toAddr;
                std::copy(r.saplingAddr.d.begin(), r.saplingAddr.d.end(), toAddr.begin());
                std::copy(r.saplingAddr.pk_d.begin(), r.saplingAddr.pk_d.end(), toAddr.begin() + 11);
                if (!builder.AddSaplingOutputNoOvk(toAddr, r.amount)) {
                    if (!selectedNullifiers.empty()) km.UnreserveNotesByNullifier(selectedNullifiers);
                    for (const auto& op : lockedCoins) m_wallet->UnlockCoin(op);
                    throw std::runtime_error("Failed to add shielded output");
                }
            } else {
                CScript scriptPubKey = GetScriptForDestination(r.transparentDest);
                builder.AddTransparentOutput(scriptPubKey, r.amount);
            }
        }

        // Release cs_wallet before Groth16 proof generation (slow, 1-30s).
        // All inputs have been collected above; the builder owns them now.
        wallet_lock.unlock();

        // Build (creates Sapling proofs + binding signature, expensive)
        std::string buildError;
        auto mtx = builder.Build(&buildError);
        if (!mtx) {
            wallet_lock.lock();
            if (!selectedNullifiers.empty()) km.UnreserveNotesByNullifier(selectedNullifiers);
            for (const auto& op : lockedCoins) m_wallet->UnlockCoin(op);
            throw std::runtime_error("Failed to build Sapling transaction: " + buildError);
        }

        // Reacquire cs_wallet for signing and commit
        wallet_lock.lock();

        // Check for reorg during proof generation; anchor may be stale
        if (m_wallet->GetLastBlockHeight() != tipHeight) {
            if (!selectedNullifiers.empty()) km.UnreserveNotesByNullifier(selectedNullifiers);
            for (const auto& op : lockedCoins) m_wallet->UnlockCoin(op);
            throw std::runtime_error("Chain tip changed during proof generation, anchor may be stale, please retry");
        }

        // Verify wallet is still unlocked after reacquiring lock
        if (m_wallet->IsLocked()) {
            if (!selectedNullifiers.empty()) km.UnreserveNotesByNullifier(selectedNullifiers);
            for (const auto& op : lockedCoins) m_wallet->UnlockCoin(op);
            throw std::runtime_error("Wallet was locked during proof generation");
        }

        // Sign transparent inputs (requires cs_wallet)
        if (!mtx->vin.empty()) {
            if (!m_wallet->SignTransaction(*mtx)) {
                if (!selectedNullifiers.empty()) km.UnreserveNotesByNullifier(selectedNullifiers);
                for (const auto& op : lockedCoins) m_wallet->UnlockCoin(op);
                throw std::runtime_error("Failed to sign transparent inputs");
            }
        }

        CTransactionRef tx = MakeTransactionRef(std::move(*mtx));

        // Fee sanity check
        if (txFee > m_wallet->m_default_max_tx_fee) {
            if (!selectedNullifiers.empty()) km.UnreserveNotesByNullifier(selectedNullifiers);
            for (const auto& op : lockedCoins) m_wallet->UnlockCoin(op);
            throw std::runtime_error("Fee exceeds wallet maximum");
        }

        // Validate transaction before committing
        TxValidationState txState;
        if (!CheckTransaction(*tx, txState)) {
            if (!selectedNullifiers.empty()) km.UnreserveNotesByNullifier(selectedNullifiers);
            for (const auto& op : lockedCoins) m_wallet->UnlockCoin(op);
            throw std::runtime_error("Transaction validation failed: " + txState.ToString());
        }

        unsigned int nMaxTxSize = (tx->nType == TRANSACTION_SAPLING)
            ? MAX_SAPLING_TX_EXTRA_PAYLOAD
            : MAX_STANDARD_TX_SIZE;
        if (GetSerializeSize(*tx) > nMaxTxSize) {
            if (!selectedNullifiers.empty()) km.UnreserveNotesByNullifier(selectedNullifiers);
            for (const auto& op : lockedCoins) m_wallet->UnlockCoin(op);
            throw std::runtime_error("Transaction too large");
        }

        // #743: Wrap CommitTransaction to unreserve notes on failure (matches RPC path)
        try {
            m_wallet->CommitTransaction(tx, {}, {});
        } catch (...) {
            if (!selectedNullifiers.empty()) km.UnreserveNotesByNullifier(selectedNullifiers);
            for (const auto& op : lockedCoins) m_wallet->UnlockCoin(op);
            throw;
        }
        if (!selectedNullifiers.empty()) km.UnreserveNotesByNullifier(selectedNullifiers);
        for (const auto& op : lockedCoins) m_wallet->UnlockCoin(op);
        return tx->GetHash().GetHex();
    }
    wallet::isminetype txinIsMine(const CTxIn& txin) override
    {
        LOCK(m_wallet->cs_wallet);
        return InputIsMine(*m_wallet, txin);
    }
    wallet::isminetype txoutIsMine(const CTxOut& txout) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsMine(txout);
    }
    CAmount getDebit(const CTxIn& txin, wallet::isminefilter filter) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetDebit(txin, filter);
    }
    CAmount getCredit(const CTxOut& txout, wallet::isminefilter filter) override
    {
        LOCK(m_wallet->cs_wallet);
        return OutputGetCredit(*m_wallet, txout, filter);
    }
    CoinsList listCoins() override
    {
        LOCK(m_wallet->cs_wallet);
        CoinsList result;
        for (const auto& entry : ListCoins(*m_wallet)) {
            auto& group = result[entry.first];
            for (const auto& coin : entry.second) {
                group.emplace_back(coin.outpoint,
                    MakeWalletTxOut(*m_wallet, coin));
            }
        }
        return result;
    }
    std::vector<WalletTxOut> getCoins(const std::vector<COutPoint>& outputs) override
    {
        LOCK(m_wallet->cs_wallet);
        std::vector<WalletTxOut> result;
        result.reserve(outputs.size());
        for (const auto& output : outputs) {
            result.emplace_back();
            auto it = m_wallet->mapWallet.find(output.hash);
            if (it != m_wallet->mapWallet.end()) {
                int depth = m_wallet->GetTxDepthInMainChain(it->second);
                if (depth >= 0) {
                    result.back() = MakeWalletTxOut(*m_wallet, it->second, output.n, depth);
                }
            }
        }
        return result;
    }
    CAmount getRequiredFee(unsigned int tx_bytes) override { return GetRequiredFee(*m_wallet, tx_bytes); }
    CAmount getMinimumFee(unsigned int tx_bytes,
        const CCoinControl& coin_control,
        int* returned_target,
        FeeReason* reason) override
    {
        FeeCalculation fee_calc;
        CAmount result;
        result = GetMinimumFee(*m_wallet, tx_bytes, coin_control, &fee_calc);
        if (returned_target) *returned_target = fee_calc.returnedTarget;
        if (reason) *reason = fee_calc.reason;
        return result;
    }
    unsigned int getConfirmTarget() override { return m_wallet->m_confirm_target; }
    bool hdEnabled() override { return m_wallet->IsHDEnabled(); }
    bool canGetAddresses() override { return m_wallet->CanGetAddresses(); }
    bool hasExternalSigner() override { return m_wallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER); }
    bool privateKeysDisabled() override { return m_wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS); }
    CAmount getDefaultMaxTxFee() override { return m_wallet->m_default_max_tx_fee; }
    void remove() override
    {
        RemoveWallet(m_context, m_wallet, false /* load_on_start */);
    }
    bool isLegacy() override { return m_wallet->IsLegacy(); }
    bool getMnemonic(SecureString& mnemonic_out, SecureString& mnemonic_passphrase_out) override
    {
        LOCK(m_wallet->cs_wallet);

        mnemonic_out.clear();
        mnemonic_passphrase_out.clear();

        if (m_wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            return false;
        }

        if (m_wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
            // Descriptor wallet
            for (auto spk_man : m_wallet->GetActiveScriptPubKeyMans()) {
                if (auto desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man)) {
                    if (desc_spk_man->GetMnemonicString(mnemonic_out, mnemonic_passphrase_out)) {
                        return true;
                    }
                }
            }
            return false;
        } else {
            // Legacy wallet
            auto spk_man = m_wallet->GetLegacyScriptPubKeyMan();
            if (!spk_man) {
                return false;
            }

            CHDChain hdChainCurrent;
            if (!spk_man->GetHDChain(hdChainCurrent)) {
                return false;
            }

            // Get decrypted HD chain if wallet is encrypted
            if (m_wallet->IsCrypted()) {
                if (!spk_man->GetDecryptedHDChain(hdChainCurrent)) {
                    return false;
                }
            }

            return hdChainCurrent.GetMnemonic(mnemonic_out, mnemonic_passphrase_out);
        }
    }
    std::unique_ptr<Handler> handleUnload(UnloadFn fn) override
    {
        return MakeHandler(m_wallet->NotifyUnload.connect(fn));
    }
    std::unique_ptr<Handler> handleShowProgress(ShowProgressFn fn) override
    {
        return MakeHandler(m_wallet->ShowProgress.connect(fn));
    }
    std::unique_ptr<Handler> handleStatusChanged(StatusChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyStatusChanged.connect([fn](CWallet*) { fn(); }));
    }
    std::unique_ptr<Handler> handleAddressBookChanged(AddressBookChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyAddressBookChanged.connect(
            [fn](const CTxDestination& address, const std::string& label, bool is_mine,
                 const std::string& purpose, ChangeType status) { fn(address, label, is_mine, purpose, status); }));
    }
    std::unique_ptr<Handler> handleTransactionChanged(TransactionChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyTransactionChanged.connect(
            [fn](const uint256& txid, ChangeType status) { fn(txid, status); }));
    }
    std::unique_ptr<Handler> handleInstantLockReceived(InstantLockReceivedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyISLockReceived.connect(
            [fn]() { fn(); }));
    }
    std::unique_ptr<Handler> handleChainLockReceived(ChainLockReceivedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyChainLockReceived.connect(
            [fn](int chainLockHeight) { fn(chainLockHeight); }));
    }
    std::unique_ptr<Handler> handleWatchOnlyChanged(WatchOnlyChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyWatchonlyChanged.connect(fn));
    }
    std::unique_ptr<Handler> handleCanGetAddressesChanged(CanGetAddressesChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyCanGetAddressesChanged.connect(fn));
    }
    std::vector<Governance::Object> getGovernanceObjects() override
    {
        LOCK(m_wallet->cs_wallet);
        std::vector<Governance::Object> result;
        for (const auto* obj : m_wallet->GetGovernanceObjects()) {
            result.push_back(*obj);
        }
        return result;
    }
    bool prepareProposal(const uint256& govobj_hash, CAmount fee, int32_t revision, int64_t created_time,
                         const std::string& data_hex, const COutPoint& outpoint,
                         std::string& out_fee_txid, std::string& error) override
    {
        LOCK(m_wallet->cs_wallet);
        CTransactionRef tx;
        if (!GenBudgetSystemCollateralTx(*m_wallet, tx, govobj_hash, fee, outpoint)) {
            error = "Error making collateral transaction for governance object.";
            return false;
        }
        // Commit tx first, then persist metadata to prevent dangling records.
        // Once commit succeeds the collateral is spent; always return success
        // with the txid. Metadata write failure is a warning, not fatal.
        try {
            m_wallet->CommitTransaction(tx, {}, {});
        } catch (const std::exception& e) {
            error = strprintf("Transaction commit failed: %s", e.what());
            return false;
        }
        if (!m_wallet->WriteGovernanceObject(Governance::Object{uint256{}, revision, created_time, tx->GetHash(), data_hex})) {
            LogPrintf("WARNING: prepareGovernanceObject: collateral %s committed but WriteGovernanceObject failed, "
                      "prepared-object tracking record missing. Do not retry (collateral already spent).\n",
                      tx->GetHash().ToString());
        }
        out_fee_txid = tx->GetHash().ToString();
        return true;
    }
    bool signGovernanceVote(const CKeyID& keyID, CGovernanceVote& vote) override
    {
        return m_wallet->SignGovernanceVote(keyID, vote);
    }
    CWallet* wallet() override { return m_wallet.get(); }

    WalletContext& m_context;
    std::shared_ptr<CWallet> m_wallet;
};

class WalletLoaderImpl : public WalletLoader
{
private:
    void RegisterRPCs(const Span<const CRPCCommand>& commands)
    {
        for (const CRPCCommand& command : commands) {
            m_rpc_commands.emplace_back(command.category, command.name, [this, &command](const JSONRPCRequest& request, UniValue& result, bool last_handler) {
                JSONRPCRequest wallet_request = request;
                wallet_request.context = m_context;
                return command.actor(wallet_request, result, last_handler);
            }, command.argNames, command.unique_id);
            m_rpc_handlers.emplace_back(m_context.chain->handleRpc(m_rpc_commands.back()));
        }
    }

public:
    WalletLoaderImpl(Chain& chain, ArgsManager& args, NodeContext& node_context)
    {
        m_context.chain = &chain;
        m_context.args = &args;
        m_context.node_context = &node_context;
    }
    ~WalletLoaderImpl() override { UnloadWallets(m_context); }

    //! ChainClient methods
    void registerRpcs() override
    {
        RegisterRPCs(GetWalletRPCCommands());
    }
    bool verify() override { return VerifyWallets(m_context); }
    bool load() override { return LoadWallets(m_context); }
    void start(CScheduler& scheduler) override { return StartWallets(m_context, scheduler); }
    void flush() override { return FlushWallets(m_context); }
    void stop() override { return StopWallets(m_context); }
    void setMockTime(int64_t time) override { return SetMockTime(time); }

    //! WalletLoader methods
    void registerOtherRpcs(const Span<const CRPCCommand>& commands) override
    {
        return RegisterRPCs(commands);
    }
    util::Result<std::unique_ptr<Wallet>> createWallet(const std::string& name, const SecureString& passphrase, uint64_t wallet_creation_flags, std::vector<bilingual_str>& warnings) override
    {
        DatabaseOptions options;
        DatabaseStatus status;
        ReadDatabaseArgs(*m_context.args, options);
        options.require_create = true;
        options.create_flags = wallet_creation_flags;
        options.create_passphrase = passphrase;
        bilingual_str error;
        std::unique_ptr<Wallet> wallet{MakeWallet(m_context, CreateWallet(m_context, name, /*load_on_start=*/true, options, status, error, warnings))};
        if (wallet) {
            return {std::move(wallet)};
        } else {
            return util::Error{error};
        }
    }
    util::Result<std::unique_ptr<Wallet>> loadWallet(const std::string& name, std::vector<bilingual_str>& warnings) override
    {
        DatabaseOptions options;
        DatabaseStatus status;
        ReadDatabaseArgs(*m_context.args, options);
        options.require_existing = true;
        bilingual_str error;
        std::unique_ptr<Wallet> wallet{MakeWallet(m_context, LoadWallet(m_context, name, /*load_on_start=*/true, options, status, error, warnings))};
        if (wallet) {
            return {std::move(wallet)};
        } else {
            return util::Error{error};
        }
    }
    util::Result<std::unique_ptr<Wallet>> restoreWallet(const fs::path& backup_file, const std::string& wallet_name, std::vector<bilingual_str>& warnings) override
    {
        DatabaseStatus status;
        bilingual_str error;
        std::unique_ptr<Wallet> wallet{MakeWallet(m_context, RestoreWallet(m_context, backup_file, wallet_name, /*load_on_start=*/true, status, error, warnings))};
        if (wallet) {
            return {std::move(wallet)};
        } else {
            return util::Error{error};
        }
    }
    std::string getWalletDir() override
    {
        return fs::PathToString(GetWalletDir());
    }
    std::vector<std::string> listWalletDir() override
    {
        std::vector<std::string> paths;
        for (auto& path : ListDatabases(GetWalletDir())) {
            paths.push_back(fs::PathToString(path));
        }
        return paths;
    }
    std::vector<std::unique_ptr<Wallet>> getWallets() override
    {
        std::vector<std::unique_ptr<Wallet>> wallets;
        for (const auto& wallet : GetWallets(m_context)) {
            wallets.emplace_back(MakeWallet(m_context, wallet));
        }
        return wallets;
    }
    std::unique_ptr<Handler> handleLoadWallet(LoadWalletFn fn) override
    {
        return HandleLoadWallet(m_context, std::move(fn));
    }
    WalletContext* context() override  { return &m_context; }

    WalletContext m_context;
    const std::vector<std::string> m_wallet_filenames;
    std::vector<std::unique_ptr<Handler>> m_rpc_handlers;
    std::list<CRPCCommand> m_rpc_commands;
};
} // namespace
} // namespace wallet

namespace interfaces {
std::unique_ptr<Wallet> MakeWallet(wallet::WalletContext& context, const std::shared_ptr<wallet::CWallet>& wallet) { return wallet ? std::make_unique<wallet::WalletImpl>(context, wallet) : nullptr; }
std::unique_ptr<WalletLoader> MakeWalletLoader(Chain& chain, ArgsManager& args, NodeContext& node_context)
{
    return std::make_unique<wallet::WalletLoaderImpl>(chain, args, node_context);
}
} // namespace interfaces
