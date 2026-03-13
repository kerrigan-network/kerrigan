// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KERRIGAN_HMP_IDENTITY_H
#define KERRIGAN_HMP_IDENTITY_H

#include <bls/bls.h>
#include <uint256.h>
#include <fs.h>

#include <memory>

/**
 * CHMPIdentity -- per-daemon BLS identity for Hivemind Protocol.
 * Auto-generated on first run, persisted to hmp_identity.dat.
 * SECURITY: secret key stored unencrypted, file perms 0600.
 */
class CHMPIdentity
{
private:
    CBLSSecretKey m_secretKey;
    CBLSPublicKey m_publicKey;
    bool m_initialized{false};

    static constexpr const char* IDENTITY_FILENAME = "hmp_identity.dat";

    bool LoadFromDisk(const fs::path& datadir);
    bool SaveToDisk(const fs::path& datadir) const;

public:
    CHMPIdentity() = default;

    /** Initialize identity: load from disk or generate new keypair */
    bool Init(const fs::path& datadir);

    const CBLSPublicKey& GetPublicKey() const { return m_publicKey; }

    /** Sign a hash with this daemon's HMP secret key */
    CBLSSignature Sign(const uint256& hash) const;

    /** Compute VRF proof for committee selection.
     *  @param prevSealHash  previous block's seal hash for anti-grinding entropy */
    CBLSSignature SignVRF(const uint256& blockHash, const uint256& prevSealHash) const;

    /** Get first 32 bytes of secret key material (for zk proof circuit) */
    bool GetSecretKeyBytes(uint8_t out[32]) const;

    bool IsValid() const { return m_initialized && m_secretKey.IsValid() && m_publicKey.IsValid(); }
};

extern std::unique_ptr<CHMPIdentity> g_hmp_identity;

#endif // KERRIGAN_HMP_IDENTITY_H
