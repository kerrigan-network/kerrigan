// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license.

#ifndef BITCOIN_QT_SHIELDEDTRANSACTIONMODEL_H
#define BITCOIN_QT_SHIELDEDTRANSACTIONMODEL_H

#include <interfaces/wallet.h>

#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <QString>

#include <vector>

class WalletModel;

class ShieldedTransactionModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum Column {
        Status = 0,
        Date,
        Type,
        Address,
        Amount,
        Memo,
        Confirmations,
        NUM_COLUMNS
    };

    explicit ShieldedTransactionModel(WalletModel* walletModel, QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    QString getTxid(int row) const;
    QString getAddress(int row) const;
    QString getMemo(int row) const;

public Q_SLOTS:
    void refresh();

private:
    WalletModel* m_walletModel;
    std::vector<interfaces::Wallet::ShieldedNoteInfo> m_notes;
    int m_tipHeight{0};
};

class ShieldedTransactionFilterProxy : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    enum StatusFilter {
        All = 0,
        Received,
        Spent
    };

    explicit ShieldedTransactionFilterProxy(QObject* parent = nullptr);

    void setStatusFilter(StatusFilter filter);
    void setSearchString(const QString& str);

protected:
    bool filterAcceptsRow(int source_row, const QModelIndex& source_parent) const override;

private:
    StatusFilter m_statusFilter{All};
    QString m_searchString;
};

#endif // BITCOIN_QT_SHIELDEDTRANSACTIONMODEL_H
