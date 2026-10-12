// Copyright (c) 2011-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BITCOINADDRESSVALIDATOR_H
#define BITCOIN_QT_BITCOINADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace. Input that starts with the Sapling address prefix
 * is checked against the Bech32 character set instead.
 */
class BitcoinAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit BitcoinAddressEntryValidator(QObject *parent, bool fAllowURI = false);

    State validate(QString &input, int &pos) const override;

private:
    bool fAllowURI;
};

/** Bitcoin address widget validator, checks for a valid bitcoin address,
 * or a Sapling payment address if fAllowSapling is set.
 */
class BitcoinAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit BitcoinAddressCheckValidator(QObject *parent, bool fAllowSapling = false);

    State validate(QString &input, int &pos) const override;

private:
    bool fAllowSapling;
};

#endif // BITCOIN_QT_BITCOINADDRESSVALIDATOR_H
