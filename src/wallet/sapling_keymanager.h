// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license.

#ifndef KERRIGAN_WALLET_SAPLING_KEYMANAGER_H
#define KERRIGAN_WALLET_SAPLING_KEYMANAGER_H

#include <sapling/sapling_address.h>
#include <wallet/crypter.h>
#include <wallet/sapling_notedata.h>
#include <sync.h>
#include <uint256.h>

#include <map>
#include <optional>
#include <set>
#include <vector>

class CBlock;
class CTransaction;
struct SaplingTxPayload;

namespace wallet {
class WalletBatch;

/**
 * Manages Sapling key material for a wallet.
 *
 * Stores extended spending keys, full viewing keys, incoming viewing keys,
 * and their associated diversified payment addresses. Provides methods for
 * key generation, address derivation, and key import/export.
 *
 * This is intentionally NOT a subclass of ScriptPubKeyMan because Sapling
 * operates on payment addresses and note commitments, not CScript.
 *
 * Key derivation is performed via Rust FFI calls to the sapling-crypto crate
 * (ZIP 32 hierarchical deterministic key derivation).
 */
class SaplingKeyManager
{
private:
    mutable Mutex cs;

    /** Map from IVK -> set of payment addresses derived from that IVK */
    std::map<sapling::SaplingIncomingViewingKey, std::set<sapling::SaplingPaymentAddress>> mapIvkToAddresses GUARDED_BY(cs);

    /** Map from payment address -> IVK (reverse lookup) */
    std::map<sapling::SaplingPaymentAddress, sapling::SaplingIncomingViewingKey> mapAddressToIvk GUARDED_BY(cs);

    /** Set of all IVKs we can spend with (have spending key) */
    std::set<sapling::SaplingIncomingViewingKey> setSpendableIvks GUARDED_BY(cs);

    /** Map from IVK -> full viewing key (96 bytes: ak || nk || ovk) */
    std::map<sapling::SaplingIncomingViewingKey, sapling::SaplingFullViewingKey> mapIvkToFvk GUARDED_BY(cs);

    /** Map from IVK -> diversifier key (32 bytes, needed for address derivation) */
    std::map<sapling::SaplingIncomingViewingKey, std::array<uint8_t, 32>> mapIvkToDk GUARDED_BY(cs);

    /** Map from IVK -> extended spending key (169 bytes, for spendable keys only, only populated when unlocked) */
    std::map<sapling::SaplingIncomingViewingKey, sapling::SaplingExtendedSpendingKey> mapIvkToExtSk GUARDED_BY(cs);

    /** Map from IVK -> encrypted spending key (populated when wallet is encrypted) */
    std::map<sapling::SaplingIncomingViewingKey, std::vector<unsigned char>> mapIvkToCryptedExtSk GUARDED_BY(cs);

    /** Whether the key manager is using encrypted key storage */
    bool fUseCrypto GUARDED_BY(cs) {false};

    /** The IVK of the "default" spending key used by GenerateNewAddress */
    std::optional<sapling::SaplingIncomingViewingKey> defaultIvk GUARDED_BY(cs);

    /** Diversifier index counter for next address generation */
    uint64_t nDiversifierIndex GUARDED_BY(cs) {0};

    /**
     * In-memory note store: nullifier -> SaplingNoteData.
     *
     * Notes are indexed by their Sapling nullifier (32-byte uint256).
     * A nullifier of all-zeros means the note position (and therefore
     * nullifier) is not yet known (e.g. mempool output).
     */
    std::map<uint256, SaplingNoteData> mapSaplingNotes GUARDED_BY(cs);

    /** Notes currently reserved by an in-flight z_sendmany. */
    std::set<uint256> m_reservedNotes GUARDED_BY(cs);

    /** Internal helper: register a FVK+DK+IVK and derive + store the default address */
    bool AddFvkInternal(const sapling::SaplingFullViewingKey& fvk,
                        const std::array<uint8_t, 32>& dk,
                        const sapling::SaplingIncomingViewingKey& ivk) EXCLUSIVE_LOCKS_REQUIRED(cs);

public:
    SaplingKeyManager() = default;
    ~SaplingKeyManager() = default;

    SaplingKeyManager(const SaplingKeyManager&) = delete;
    SaplingKeyManager& operator=(const SaplingKeyManager&) = delete;

    /**
     * Add a Sapling spending key to the manager.
     * Derives the full viewing key, incoming viewing key, and default address
     * via Rust FFI (ZIP 32). The first spending key added becomes the default
     * key used by GenerateNewAddress().
     */
    bool AddSpendingKey(const sapling::SaplingExtendedSpendingKey& sk) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Add a viewing key (watch-only).
     * Derives IVK and default address via Rust FFI.
     * Can detect incoming notes but cannot spend them.
     */
    bool AddViewingKey(const sapling::SaplingFullViewingKey& fvk, const std::array<uint8_t, 32>& dk) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Generate a new diversified payment address from the default spending key.
     * Uses ZIP 32 find_address to find the next valid diversifier at or above
     * the current diversifier index.
     */
    std::optional<sapling::SaplingPaymentAddress> GenerateNewAddress() EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Check if a payment address belongs to this wallet.
     */
    bool HaveAddress(const sapling::SaplingPaymentAddress& addr) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Check if we can spend from a given address (have the spending key).
     */
    bool CanSpend(const sapling::SaplingPaymentAddress& addr) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Register a diversified payment address discovered while building a
     * spend (typically an internal ZIP 316 change address whose diversifier
     * is chosen at tx-build time and is not derivable from persisted state).
     *
     * Inserts the address into mapAddressToIvk / mapIvkToAddresses so
     * CanSpend() and GetUnspentNotes(addr) recognise it, and optionally
     * persists the mapping through @p batch so it survives a restart.
     *
     * Requires @p ivk to already be known to the wallet (i.e. in
     * mapIvkToFvk). If the IVK is unknown, the call is a no-op and returns
     * false. Idempotent: safe to call repeatedly for the same (addr, ivk).
     *
     * @param addr   Payment address to register.
     * @param ivk    Incoming viewing key that decrypts notes sent to @p addr.
     * @param batch  If non-null, persist the address->ivk mapping via the
     *               caller's WalletBatch. If null, registration is
     *               in-memory only (the load path re-derives it).
     * @return true if the mapping was inserted (or already present),
     *         false if @p ivk is not tracked by this wallet or the
     *         DB write failed.
     */
    bool RegisterDiversifiedAddress(const sapling::SaplingPaymentAddress& addr,
                                    const sapling::SaplingIncomingViewingKey& ivk,
                                    WalletBatch* batch = nullptr) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Get the incoming viewing key for a payment address.
     */
    std::optional<sapling::SaplingIncomingViewingKey> GetIvk(const sapling::SaplingPaymentAddress& addr) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Get the extended spending key for a payment address.
     * Returns nullopt if no spending key is available (watch-only or unknown).
     */
    std::optional<sapling::SaplingExtendedSpendingKey> GetSpendingKey(const sapling::SaplingPaymentAddress& addr) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Get the full viewing key for a payment address.
     * Returns nullopt if the address is unknown. FVK contains ak, nk, ovk.
     */
    std::optional<sapling::SaplingFullViewingKey> GetFvk(const sapling::SaplingPaymentAddress& addr) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Get the diversifier key (32 bytes) for a payment address.
     * Returns nullopt if the address is unknown.
     * Needed for derive_internal_fvk() to generate unlinkable change addresses.
     */
    std::optional<std::array<uint8_t, 32>> GetDk(const sapling::SaplingPaymentAddress& addr) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Get all payment addresses belonging to this wallet.
     */
    std::vector<sapling::SaplingPaymentAddress> GetAllAddresses() const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Get all incoming viewing keys (for trial decryption during scanning).
     */
    std::vector<sapling::SaplingIncomingViewingKey> GetAllIvks() const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Check if a given IVK is already tracked by this manager.
     */
    bool HaveIvk(const sapling::SaplingIncomingViewingKey& ivk) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Check whether an IVK corresponds to an external (user-facing) spending key
     * rather than an internal ZIP 316 change key.
     *
     * An IVK is classified as internal if the ExtSK stored for it is the
     * xsk_derive_internal() output of some other ExtSK also tracked by this
     * manager. Such IVKs must not be exported via dumpwallet: on re-import,
     * AddSpendingKey() re-derives the internal ExtSK from the external one
     * automatically. Treating an internal ExtSK as external on import would
     * corrupt defaultIvk and restart external-address diversifier derivation
     * from j=0, breaking round-trip of dumpwallet->importwallet.
     *
     * Returns:
     *   - true  if @p ivk has a spending key and that key is NOT an internal
     *           derivation of any other tracked ExtSK (i.e. it is external).
     *   - false if @p ivk is internal, watch-only, or unknown.
     */
    bool IsExternalIvk(const sapling::SaplingIncomingViewingKey& ivk) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Return the ZIP 32 default (j=0) external payment address for @p ivk.
     *
     * Re-derives the default address via fvk_default_address() rather than
     * picking one of the diversified addresses already stored under this IVK
     * (the stored set is ordered by address bytes, not diversifier index).
     *
     * Used by dumpwallet to emit a stable, human-recognisable address for
     * each exported spending key.
     *
     * Returns nullopt if @p ivk is unknown or FFI derivation fails.
     */
    std::optional<sapling::SaplingPaymentAddress> GetDefaultExternalAddress(const sapling::SaplingIncomingViewingKey& ivk) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Returns true if any Sapling keys are loaded.
     */
    bool IsEmpty() const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Returns the number of spendable IVKs (spending keys loaded).
     */
    size_t GetSpendableKeyCount() const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Returns the total number of tracked Sapling notes (spent + unspent).
     */
    size_t GetNoteCount() const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Post-load consistency check. Verifies that:
     *  - Every spending key has a corresponding FVK record
     *  - The stored FVK matches the FVK re-derived from the spending key
     *  - Every FVK has at least one associated address
     *
     * Logs warnings for inconsistencies but does not abort wallet load.
     * Returns the number of inconsistencies found (0 = fully consistent).
     */
    int ValidateConsistency() const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    // Note tracking

    /**
     * Scan all OutputDescriptions in a confirmed Sapling transaction.
     * For each output, tries every wallet IVK via Rust FFI note decryption.
     * Successfully decrypted notes are stored in mapSaplingNotes.
     *
     * @param tx          The transaction containing the Sapling payload.
     * @param payload     Parsed SaplingTxPayload (spends + outputs).
     * @param blockHeight Confirmed height (-1 for mempool).
     * @param networkIDStr "main", "test", or "regtest" (for Rust FFI).
     * @param saplingHeight Sapling activation height (for regtest Rust network).
     */
    void ScanSaplingOutputs(const CTransaction& tx,
                            const SaplingTxPayload& payload,
                            int blockHeight,
                            const std::string& networkIDStr,
                            int saplingHeight,
                            WalletBatch* batch = nullptr) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Scan all SpendDescriptions in a Sapling transaction.
     * For each spend whose nullifier matches a stored note, mark that note spent.
     *
     * @param tx      The spending transaction.
     * @param payload Parsed SaplingTxPayload.
     */
    void ScanSaplingSpends(const CTransaction& tx,
                           const SaplingTxPayload& payload,
                           WalletBatch* batch = nullptr) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Update incremental Merkle witnesses for all unspent wallet notes.
     *
     * Called from CWallet::blockConnected after ScanSaplingOutputs/Spends,
     * with the ordered list of all note commitments from the block.
     *
     * For each commitment:
     *  1. Appends to the frontier (for root tracking)
     *  2. Updates all existing witnesses (authentication path maintenance)
     *  3. Creates a new witness for any owned note in this block
     *
     * @param blockHeight Height of the connected block.
     * @param blockCmus   All Sapling note commitments from the block, in order.
     */
    void UpdateWitnesses(int blockHeight, const std::vector<uint256>& blockCmus,
                         WalletBatch* batch = nullptr) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Total confirmed unspent Sapling balance across all wallet notes.
     */
    CAmount GetSaplingBalance() const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Confirmed unspent Sapling balance for a specific payment address.
     */
    CAmount GetSaplingBalance(const sapling::SaplingPaymentAddress& addr) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Reserve notes for an in-flight transaction to prevent double-selection
     * when cs_wallet is released during proof generation.
     */
    void ReserveNotes(const std::set<uint256>& cmus) EXCLUSIVE_LOCKS_REQUIRED(!cs);
    void UnreserveNotes(const std::set<uint256>& cmus) EXCLUSIVE_LOCKS_REQUIRED(!cs);
    void ReserveNotesByNullifier(const std::set<uint256>& nullifiers) EXCLUSIVE_LOCKS_REQUIRED(!cs);
    void UnreserveNotesByNullifier(const std::set<uint256>& nullifiers) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * All tracked notes (spent + unspent), keyed by cmu.
     */
    std::vector<std::pair<uint256, SaplingNoteData>> GetAllNotes() const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * All confirmed unspent notes (excludes reserved notes).
     */
    std::vector<SaplingNoteData> GetUnspentNotes() const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * All confirmed unspent notes for a specific payment address (excludes reserved).
     */
    std::vector<SaplingNoteData> GetUnspentNotes(const sapling::SaplingPaymentAddress& addr) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Unspent notes with their cmu keys, for reservation tracking.
     */
    std::vector<std::pair<uint256, SaplingNoteData>> GetUnspentNotesWithKeys(const sapling::SaplingPaymentAddress& addr) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Remove notes created by zapped transactions and clear spend state
     * for notes whose spending transaction was zapped.
     *
     * Called from CWallet::ZapSelectTx() to keep Sapling note state
     * consistent with the transparent wallet.
     */
    void ZapNotesByTxid(const std::set<uint256>& txids, WalletBatch* batch = nullptr) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    // Encryption

    /**
     * One-time encryption of all in-memory spending keys using the wallet master key.
     * Called from CWallet::EncryptWallet(). Writes crypted keys to DB and clears plaintext.
     */
    bool EncryptKeys(const CKeyingMaterial& vMasterKey, WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Decrypt and restore all spending keys to memory.
     * Called from CWallet::Unlock() after verifying the passphrase.
     */
    bool Unlock(const CKeyingMaterial& vMasterKey) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Clear all plaintext spending keys from memory (called from CWallet::Lock()).
     */
    void Lock() EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Returns true if the key manager is in encrypted (locked or unlocked) mode.
     */
    bool IsCrypto() const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    // DB load helpers (called by WalletBatch during wallet open)

    /**
     * Load a persisted note from the DB into mapSaplingNotes.
     * Called during wallet open for each SAPLING_NOTE record.
     */
    void LoadNote(const uint256& cmu, const SaplingNoteData& nd) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Load a spending key from the DB. Unlike AddSpendingKey(), this does not
     * call Rust FFI to re-derive keys; all data is already stored on disk.
     * The FVK/DK/IVK records for this key must be loaded via LoadViewingKey
     * before or after this call.
     */
    bool LoadSpendingKey(const sapling::SaplingIncomingViewingKey& ivk,
                         const sapling::SaplingExtendedSpendingKey& sk) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Load an encrypted spending key from the DB.
     * Called during wallet open when wallet is encrypted.
     */
    void LoadCryptedSpendingKey(const sapling::SaplingIncomingViewingKey& ivk,
                                const std::vector<unsigned char>& vchCryptedSecret) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Load a full viewing key + DK from the DB. Registers the FVK and DK keyed
     * by IVK. Does not derive addresses (those come from LoadAddress records).
     */
    bool LoadViewingKey(const sapling::SaplingIncomingViewingKey& ivk,
                        const sapling::SaplingFullViewingKey& fvk,
                        const std::array<uint8_t, 32>& dk) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Load a payment address -> IVK mapping from the DB.
     * The IVK must already be loaded via LoadViewingKey.
     */
    void LoadAddress(const sapling::SaplingPaymentAddress& addr,
                     const sapling::SaplingIncomingViewingKey& ivk) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Load a persisted diversifier index from the DB.
     */
    void LoadDiversifierIndex(uint64_t index) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    // DB persistence hooks (called by AddSpendingKey/AddViewingKey)

    /**
     * Persist a spending key to the DB immediately after it is added.
     * If vMasterKey is provided and the wallet is encrypted, the key is encrypted
     * before being written to DB (required when importing into an encrypted wallet).
     */
    bool AddSpendingKeyWithDB(WalletBatch& batch, const sapling::SaplingExtendedSpendingKey& sk,
                              const CKeyingMaterial* vMasterKey = nullptr) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Persist a viewing key to the DB immediately after it is added.
     */
    bool AddViewingKeyWithDB(WalletBatch& batch, const sapling::SaplingFullViewingKey& fvk, const std::array<uint8_t, 32>& dk) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Persist a payment address to the DB. Called after generating a new address.
     */
    bool WriteAddressToDB(WalletBatch& batch, const sapling::SaplingPaymentAddress& addr) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Persist the current diversifier index to the DB.
     * The index is keyed by the hash of the default IVK.
     */
    bool WriteDiversifierIndexToDB(WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Clear witness data for all unspent confirmed notes, and return the minimum
     * block height of any such note (or std::nullopt if no unspent notes exist).
     *
     * Used by z_rebuildsaplingwitnesses to force a full witness replay when the
     * wallet's per-note witness state has become stale relative to the authoritative
     * Sapling frontier (e.g. after a daemon stall, LevelDB rebuild, or IBD re-catchup).
     * Spent notes are left untouched; their witnesses are no longer needed.
     */
    std::optional<int> ClearWitnessesForRebuild(WalletBatch* batch = nullptr) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Inspection result for a single note during stale-witness detection.
     */
    struct StaleWitnessReport {
        uint256 cmu;               //!< Note commitment (map key).
        int blockHeight{-1};       //!< Height at which the note was confirmed.
        std::string reason;        //!< Human-readable reason the witness is stale.
    };

    /**
     * Scan every unspent confirmed note and identify those whose serialized
     * witness is unusable.
     *
     * Witnesses are maintained in lockstep: every time UpdateWitnesses()
     * processes a block, all live witnesses get the same new leaves appended,
     * so their Merkle root must equal the consensus Sapling anchor at the
     * wallet's current tip height. If any unspent witness's root disagrees,
     * its state drifted (typically because a frontier-deserialize failure
     * made UpdateWitnesses bail out on some prior block) and it must be
     * rebuilt.
     *
     * A witness is flagged as stale if:
     *   - witnessData is empty for a confirmed, unspent note; or
     *   - witness_deserialize() or witness_root() throws; or
     *   - witness_root() does not match the Sapling anchor at @p walletTipHeight.
     *
     * Read-only: does not mutate note state. The caller (auto-rebuild or
     * diagnostic tooling) decides what to do with the report.
     *
     * Complexity: O(N) in wallet notes; two Rust FFI calls and one SaplingDB
     * read per note. Intended to run once at wallet startup / IBD completion,
     * not on every block.
     *
     * @param walletTipHeight  Height of the last block the wallet processed
     *                         (i.e. m_last_block_processed_height). A value
     *                         < 0 suppresses the anchor check and only
     *                         reports deserialize failures or empty witnesses.
     * @return one StaleWitnessReport per note flagged as stale.
     */
    std::vector<StaleWitnessReport> DetectStaleWitnesses(int walletTipHeight) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Rewind Sapling state for a disconnected block.
     *
     * Undoes spends (clears isSpent/spendingTxid), reverts outputs confirmed
     * at this height, and clears stale witness data from earlier blocks.
     * Notes are never erased; they remain as unconfirmed entries and will be
     * re-confirmed if they appear in the new fork.
     */
    void RewindBlock(int height, const CBlock& block, WalletBatch* batch = nullptr) EXCLUSIVE_LOCKS_REQUIRED(!cs);
};

} // namespace wallet

#endif // KERRIGAN_WALLET_SAPLING_KEYMANAGER_H
