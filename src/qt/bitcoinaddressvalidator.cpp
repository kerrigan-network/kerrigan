// Copyright (c) 2011-2014 The Bitcoin Core developers
// Copyright (c) 2014-2023 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bitcoinaddressvalidator.h>
#include <qt/guiutil.h>

#include <chainparams.h>
#include <key_io.h>
#include <sapling/sapling_address.h>

/* Base58 characters are:
     "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  This is:
  - All numbers except for '0'
  - All upper-case letters except for 'I' and 'O'
  - All lower-case letters except for 'l'

  Sapling addresses are Bech32m: "<hrp>1" followed by characters from
     "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
  in either all lower case or all upper case.
*/

namespace {
const QString BECH32_CHARSET = QStringLiteral("qpzry9x8gf2tvdw0s3jn54khce6mua7l");
} // namespace

BitcoinAddressEntryValidator::BitcoinAddressEntryValidator(QObject *parent, bool fAllowURI) :
    QValidator(parent), fAllowURI(fAllowURI)
{
}

QValidator::State BitcoinAddressEntryValidator::validate(QString &input, int &pos) const
{
    Q_UNUSED(pos);

    // Empty address is "intermediate" input
    if (input.isEmpty())
        return QValidator::Intermediate;

    if (fAllowURI && GUIUtil::validateBitcoinURI(input)) {
        return QValidator::Acceptable;
    }

    // Correction
    for (int idx = 0; idx < input.size();)
    {
        bool removeChar = false;
        QChar ch = input.at(idx);
        // Corrections made are very conservative on purpose, to avoid
        // users unexpectedly getting away with typos that would normally
        // be detected, and thus sending to the wrong address.
        switch(ch.unicode())
        {
        // Qt categorizes these as "Other_Format" not "Separator_Space"
        case 0x200B: // ZERO WIDTH SPACE
        case 0xFEFF: // ZERO WIDTH NO-BREAK SPACE
            removeChar = true;
            break;
        default:
            break;
        }

        // Remove whitespace
        if (ch.isSpace())
            removeChar = true;

        // To next character
        if (removeChar)
            input.remove(idx, 1);
        else
            ++idx;
    }

    // Sapling address (Bech32m), or a prefix of its human-readable part
    const QString sapling_prefix = QString::fromStdString(Params().SaplingHRP()) + QLatin1Char('1');
    const QString lower = input.toLower();
    if (sapling_prefix.startsWith(lower)) {
        return QValidator::Acceptable;
    }
    if (lower.startsWith(sapling_prefix) && (input == lower || input == input.toUpper())) {
        bool bech32 = true;
        for (int idx = sapling_prefix.size(); idx < lower.size(); ++idx) {
            if (!BECH32_CHARSET.contains(lower.at(idx))) {
                bech32 = false;
                break;
            }
        }
        if (bech32) {
            return QValidator::Acceptable;
        }
        // Otherwise fall through: it may still be a Base58 address
    }

    // Validation
    QValidator::State state = QValidator::Acceptable;
    for (int idx = 0; idx < input.size(); ++idx)
    {
        int ch = input.at(idx).unicode();

        if (((ch >= '0' && ch<='9') ||
            (ch >= 'a' && ch<='z') ||
            (ch >= 'A' && ch<='Z')) &&
            ch != 'l' && ch != 'I' && ch != '0' && ch != 'O')
        {
            // Alphanumeric and not a 'forbidden' character
        }
        else
        {
            state = QValidator::Invalid;
        }
    }

    return state;
}

BitcoinAddressCheckValidator::BitcoinAddressCheckValidator(QObject *parent, bool fAllowSapling) :
    QValidator(parent), fAllowSapling(fAllowSapling)
{
}

QValidator::State BitcoinAddressCheckValidator::validate(QString &input, int &pos) const
{
    Q_UNUSED(pos);
    // Validate the passed Kerrigan address
    if (IsValidDestinationString(input.toStdString())) {
        return QValidator::Acceptable;
    }
    sapling::SaplingPaymentAddress sapling_addr;
    if (fAllowSapling && DecodeSaplingAddress(input.toStdString(), sapling_addr)) {
        return QValidator::Acceptable;
    }

    return QValidator::Invalid;
}
