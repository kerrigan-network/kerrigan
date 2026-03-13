// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hmp/identity.h>

#include <clientversion.h>
#include <logging.h>
#include <random.h>
#include <support/cleanse.h>
#include <hmp/vrf.h>
#include <streams.h>
#include <util/system.h>

#ifndef WIN32
#include <sys/stat.h>
#endif

static constexpr uint8_t HMP_IDENTITY_MAGIC[4] = {'H', 'M', 'P', 'I'};
static constexpr uint8_t HMP_IDENTITY_VERSION = 1;

bool CHMPIdentity::LoadFromDisk(const fs::path& datadir)
{
    fs::path filepath = datadir / IDENTITY_FILENAME;
    if (!fs::exists(filepath)) {
        return false;
    }

    // Warn if the identity file is world-readable (contains unencrypted BLS secret key).
#ifndef WIN32
    {
        struct stat st;
        if (stat(fs::PathToString(filepath).c_str(), &st) == 0) {
            mode_t excess = st.st_mode & (S_IRWXG | S_IRWXO); // group + other bits
            if (excess != 0) {
                LogPrintf("HMP: WARNING: %s has permissions %04o, should be 0600. "
                          "Other users may be able to read the BLS secret key.\n",
                          IDENTITY_FILENAME, (unsigned)(st.st_mode & 07777));
            }
        }
    }
#endif

    try {
        CAutoFile filein(fsbridge::fopen(filepath, "rb"), SER_DISK, CLIENT_VERSION);
        if (filein.IsNull()) {
            return false;
        }

        uint8_t magic[4];
        uint8_t version;
        filein.read(AsWritableBytes(Span{magic}));
        filein >> version;

        if (memcmp(magic, HMP_IDENTITY_MAGIC, 4) != 0 || version != HMP_IDENTITY_VERSION) {
            LogPrintf("HMP: identity file has invalid magic/version\n");
            return false;
        }

        filein >> m_secretKey;
        if (!m_secretKey.IsValid()) {
            LogPrintf("HMP: loaded secret key is invalid\n");
            auto skBytes = m_secretKey.ToByteVector(false);
            memory_cleanse(skBytes.data(), skBytes.size());
            m_secretKey = CBLSSecretKey();
            return false;
        }

        m_publicKey = m_secretKey.GetPublicKey();
        if (!m_publicKey.IsValid()) {
            LogPrintf("HMP: derived public key is invalid\n");
            auto skBytes = m_secretKey.ToByteVector(false);
            memory_cleanse(skBytes.data(), skBytes.size());
            m_secretKey = CBLSSecretKey();
            return false;
        }

        return true;
    } catch (const std::exception& e) {
        LogPrintf("HMP: failed to load identity: %s\n", e.what());
        return false;
    }
}

bool CHMPIdentity::SaveToDisk(const fs::path& datadir) const
{
    fs::path filepath = datadir / IDENTITY_FILENAME;
    fs::path tmppath = filepath;
    tmppath += ".tmp";

    try {
#ifndef WIN32
        // 0600 umask
        mode_t old_umask = umask(S_IRWXG | S_IRWXO);
#endif
        CAutoFile fileout(fsbridge::fopen(tmppath, "wb"), SER_DISK, CLIENT_VERSION);
#ifndef WIN32
        umask(old_umask);
#endif
        if (fileout.IsNull()) {
            LogPrintf("HMP: failed to open identity file for writing\n");
            return false;
        }

        fileout.write(AsBytes(Span{HMP_IDENTITY_MAGIC}));
        fileout << HMP_IDENTITY_VERSION;
        fileout << m_secretKey;

        if (!FileCommit(fileout.Get())) {
            LogPrintf("HMP: failed to commit identity file\n");
            return false;
        }
        fileout.fclose();

        if (!RenameOver(tmppath, filepath)) {
            LogPrintf("HMP: failed to rename identity file\n");
            return false;
        }

        // 0600: identity file contains unencrypted BLS secret key
#ifndef WIN32
        if (chmod(fs::PathToString(filepath).c_str(), S_IRUSR | S_IWUSR) != 0) {
            LogPrintf("HMP: WARNING: failed to set permissions on %s\n", IDENTITY_FILENAME);
        }
#endif

        return true;
    } catch (const std::exception& e) {
        LogPrintf("HMP: failed to save identity: %s\n", e.what());
        return false;
    }
}

bool CHMPIdentity::Init(const fs::path& datadir)
{
    if (LoadFromDisk(datadir)) {
        m_initialized = true;
        LogPrintf("HMP: loaded identity pubkey=%s\n", m_publicKey.ToString().substr(0, 16));
        return true;
    }

    CBLSSecretKey newKey;
    newKey.MakeNewKey();
    if (!newKey.IsValid()) {
        LogPrintf("HMP: failed to generate new BLS keypair\n");
        return false;
    }

    m_secretKey = newKey;
    m_publicKey = m_secretKey.GetPublicKey();

    if (!SaveToDisk(datadir)) {
        LogPrintf("HMP: failed to persist new identity\n");
        return false;
    }

    m_initialized = true;
    LogPrintf("HMP: generated new identity pubkey=%s\n", m_publicKey.ToString().substr(0, 16));
    return true;
}

CBLSSignature CHMPIdentity::Sign(const uint256& hash) const
{
    if (!m_initialized) {
        return CBLSSignature();
    }
    return m_secretKey.Sign(hash, false /* not legacy scheme */);
}

CBLSSignature CHMPIdentity::SignVRF(const uint256& blockHash, const uint256& prevSealHash) const
{
    if (!m_initialized) {
        return CBLSSignature();
    }
    return ComputeVRF(m_secretKey, blockHash, prevSealHash);
}

bool CHMPIdentity::GetSecretKeyBytes(uint8_t out[32]) const
{
    if (!m_initialized || !m_secretKey.IsValid()) {
        return false;
    }
    auto buf = m_secretKey.ToByteVector(false /* not legacy */);
    if (buf.size() < 32) return false;
    memcpy(out, buf.data(), 32);
    memory_cleanse(buf.data(), buf.size());
    return true;
}
