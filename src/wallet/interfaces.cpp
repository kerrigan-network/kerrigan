// Copyright (c) 2018-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/wallet.h>

#include <chain.h>
#include <consensus/amount.h>
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
#include <random.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/fees.h>
#include <wallet/ismine.h>
#include <wallet/load.h>
#include <wallet/receive.h>
#include <wallet/rpc/wallet.h>
#include <wallet/sapling_keymanager.h>
#include <wallet/sapling_send.h>
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
        // Persist the new address record AND the advanced diversifier index
        // atomically. Mirrors the z_getnewaddress RPC site (rpc/sapling.cpp):
        // a partial-write would either leak a never-persisted address or
        // re-use the same diversifier on the next call. The in-memory counter
        // has already advanced; on a hard write failure we throw, the caller
        // does NOT see an address, and a future rescan rederives the address
        // from (defaultIvk, diversifier index).
        WalletBatch batch(m_wallet->GetDatabase());
        if (!batch.TxnBegin()) {
            throw std::runtime_error("Failed to begin wallet DB transaction for new Sapling address");
        }
        if (!km.WriteAddressToDB(batch, *addr)) {
            batch.TxnAbort();
            throw std::runtime_error("Failed to persist Sapling address");
        }
        if (!km.WriteDiversifierIndexToDB(batch)) {
            batch.TxnAbort();
            throw std::runtime_error("Failed to persist Sapling diversifier index");
        }
        if (!batch.TxnCommit()) {
            batch.TxnAbort();
            throw std::runtime_error("Failed to commit Sapling address persistence");
        }
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
    static ShieldedNoteInfo MakeShieldedNoteInfo(const uint256& cmu, const SaplingNoteData& nd)
    {
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
        return info;
    }
    std::vector<ShieldedNoteInfo> getShieldedNoteHistory() override
    {
        const auto& km = m_wallet->GetSaplingKeyManager();
        auto allNotes = km.GetAllNotes();
        std::vector<ShieldedNoteInfo> result;
        result.reserve(allNotes.size());
        for (const auto& [cmu, nd] : allNotes) {
            result.push_back(MakeShieldedNoteInfo(cmu, nd));
        }
        return result;
    }
    std::vector<ShieldedNoteInfo> getShieldedNotesForTx(const uint256& txid) override
    {
        std::vector<ShieldedNoteInfo> result;
        for (const auto& nd : m_wallet->GetSaplingKeyManager().GetNotesByTxid(txid)) {
            result.push_back(MakeShieldedNoteInfo(uint256(), nd));
        }
        return result;
    }
    std::vector<SaplingSpendableNote> listSpendableSaplingNotes(int minconf) override
    {
        return ListSpendableSaplingNotes(*m_wallet, minconf);
    }
    SaplingSendPlan planSaplingSend(const SaplingSendSource& source,
        const std::vector<SaplingSendRecipient>& recipients,
        int minconf) override
    {
        return PlanSaplingSend(*m_wallet, source, recipients, minconf);
    }
    std::string sendSapling(const SaplingSendSource& source,
        const std::vector<SaplingSendRecipient>& recipients,
        int minconf) override
    {
        return SendSapling(*m_wallet, source, recipients, minconf);
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
