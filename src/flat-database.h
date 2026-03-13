// Copyright (c) 2014-2025 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_FLAT_DATABASE_H
#define BITCOIN_FLAT_DATABASE_H

#include <clientversion.h>
#include <chainparams.h>
#include <fs.h>
#include <hash.h>
#include <streams.h>
#include <util/system.h>

/**
*   Generic Dumping and Loading
*   ---------------------------
*/

template<typename T>
class CFlatDB
{
private:
    enum class ReadResult {
        Ok,
        FileError,
        HashReadError,
        IncorrectHash,
        IncorrectMagicMessage,
        IncorrectMagicNumber,
        IncorrectFormat
    };

    fs::path pathDB;
    std::string strFilename;
    std::string strMagicMessage;

    [[nodiscard]] bool CoreWrite(const T& objToSave)
    {
        // LOCK(objToSave.cs);

        const auto start{SteadyClock::now()};

        // serialize, checksum data up to that point, then append checksum
        CDataStream ssObj(SER_DISK, CLIENT_VERSION);
        ssObj << strMagicMessage; // specific magic message for this type of object
        ssObj << Params().MessageStart(); // network specific magic number
        ssObj << objToSave;
        uint256 hash = Hash(ssObj);
        ssObj << hash;

        // Write to a temporary file first, then atomically rename into place.
        // This avoids data loss if the process crashes mid-write: the old file
        // remains intact until the rename succeeds.
        fs::path pathTmp = pathDB;
        pathTmp += ".new";

        // open temp output file, and associate with AutoFile
        FILE *file = fsbridge::fopen(pathTmp, "wb");
        AutoFile fileout{file};
        if (fileout.IsNull()) {
            return error("%s: Failed to open file %s", __func__, fs::PathToString(pathTmp));
        }

        // Write and commit header, data
        try {
            fileout << ssObj;
        }
        catch (std::exception &e) {
            fileout.fclose();
            remove(pathTmp);
            return error("%s: Serialize or I/O error - %s", __func__, e.what());
        }

        // Flush to disk before rename so data survives an OS crash
        if (!FileCommit(fileout.Get())) {
            fileout.fclose();
            remove(pathTmp);
            return error("%s: Failed to flush file %s", __func__, fs::PathToString(pathTmp));
        }
        fileout.fclose();

        // Atomically replace the old file (POSIX rename is atomic)
        if (!RenameOver(pathTmp, pathDB)) {
            remove(pathTmp);
            return error("%s: Rename-into-place failed from %s to %s", __func__,
                         fs::PathToString(pathTmp), fs::PathToString(pathDB));
        }

        LogPrintf("Written info to %s  %dms\n", strFilename, Ticks<std::chrono::milliseconds>(SteadyClock::now() - start));
        LogPrintf("     %s\n", objToSave.ToString());

        return true;
    }

    [[nodiscard]] ReadResult CoreRead(T& objToLoad)
    {
        //LOCK(objToLoad.cs);

        const auto start{SteadyClock::now()};
        // open input file, and associate with AutoFile
        FILE *file = fsbridge::fopen(pathDB, "rb");
        AutoFile filein{file};
        if (filein.IsNull()) {
            // It is not actually error, maybe it's a first initialization of core.
            return ReadResult::FileError;
        }

        // use file size to size memory buffer
        static constexpr size_t MAX_CACHE_FILE_SIZE = 256 * 1024 * 1024; // 256 MB
        auto fileSize = fs::file_size(pathDB);
        if (fileSize > MAX_CACHE_FILE_SIZE || fileSize < sizeof(uint256)) {
            error("%s: File %s size %zu exceeds safety limit or is too small", __func__, fs::PathToString(pathDB), static_cast<size_t>(fileSize));
            return ReadResult::FileError;
        }
        size_t dataSize = static_cast<size_t>(fileSize) - sizeof(uint256);
        std::vector<unsigned char> vchData;
        vchData.resize(dataSize);
        uint256 hashIn;

        // read data and checksum from file
        try {
            filein.read(MakeWritableByteSpan(vchData));
            filein >> hashIn;
        }
        catch (std::exception &e) {
            error("%s: Deserialize or I/O error - %s", __func__, e.what());
            return ReadResult::HashReadError;
        }
        filein.fclose();

        CDataStream ssObj(vchData, SER_DISK, CLIENT_VERSION);

        // verify stored checksum matches input data
        uint256 hashTmp = Hash(ssObj);
        if (hashIn != hashTmp)
        {
            error("%s: Checksum mismatch, data corrupted", __func__);
            return ReadResult::IncorrectHash;
        }


        try {
            unsigned char pchMsgTmp[4];
            std::string strMagicMessageTmp;
            // de-serialize file header (file specific magic message) and ..
            ssObj >> strMagicMessageTmp;

            // ... verify the message matches predefined one
            if (strMagicMessage != strMagicMessageTmp)
            {
                error("%s: Invalid magic message", __func__);
                return ReadResult::IncorrectMagicMessage;
            }


            // de-serialize file header (network specific magic number) and ..
            ssObj >> pchMsgTmp;

            // ... verify the network matches ours
            if (memcmp(pchMsgTmp, Params().MessageStart(), sizeof(pchMsgTmp)))
            {
                error("%s: Invalid network magic number", __func__);
                return ReadResult::IncorrectMagicNumber;
            }

            // de-serialize data into T object
            ssObj >> objToLoad;
        }
        catch (std::exception &e) {
            objToLoad.Clear();
            error("%s: Deserialize or I/O error - %s", __func__, e.what());
            return ReadResult::IncorrectFormat;
        }

        LogPrintf("Loaded info from %s  %dms\n", strFilename, Ticks<std::chrono::milliseconds>(SteadyClock::now() - start));
        LogPrintf("     %s\n", objToLoad.ToString());

        return ReadResult::Ok;
    }

    [[nodiscard]] bool Read(T& objToLoad)
    {
        ReadResult readResult = CoreRead(objToLoad);
        if (readResult == ReadResult::FileError)
            LogPrintf("Missing file %s, will try to recreate\n", strFilename);
        else if (readResult != ReadResult::Ok) {
            LogPrintf("WARNING: CFlatDB::Read Error reading %s: ", strFilename);
            if (readResult == ReadResult::IncorrectFormat) {
                LogPrintf("%s: Magic is ok but data has invalid format, will try to recreate\n", __func__);
            } else {
                // Incompatible file format (e.g. after upgrade); the cached
                // data is ephemeral and will be rebuilt at runtime.
                // Delete the stale file so the
                // daemon can start cleanly.
                LogPrintf("%s: File format is unknown or invalid, removing stale %s and starting fresh\n",
                          __func__, strFilename);
                try {
                    fs::remove(pathDB);
                } catch (const fs::filesystem_error& e) {
                    LogPrintf("WARNING: Could not remove %s: %s\n", strFilename, e.what());
                }
            }
        }
        return true;
    }

public:
    CFlatDB(std::string&& strFilenameIn, std::string&& strMagicMessageIn) :
        pathDB{gArgs.GetDataDirNet() / fs::u8path(strFilenameIn)},
        strFilename{strFilenameIn},
        strMagicMessage{strMagicMessageIn}
    {
    }

    [[nodiscard]] bool Load(T& objToLoad)
    {
        LogPrintf("Reading info from %s...\n", strFilename);
        return Read(objToLoad);
    }

    bool Store(const T& objToSave)
    {
        LogPrintf("Verifying %s format...\n", strFilename);
        T tmpObjToLoad;
        if (!Read(tmpObjToLoad)) return false;

        const auto start{SteadyClock::now()};

        LogPrintf("Writing info to %s...\n", strFilename);
        const bool ret = CoreWrite(objToSave);
        LogPrintf("%s dump finished  %dms\n", strFilename, Ticks<std::chrono::milliseconds>(SteadyClock::now() - start));

        return ret;
    }
};


#endif // BITCOIN_FLAT_DATABASE_H
