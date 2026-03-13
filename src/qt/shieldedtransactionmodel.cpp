// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license.

#include <qt/shieldedtransactionmodel.h>

#include <qt/bitcoinunits.h>
#include <qt/optionsmodel.h>
#include <qt/walletmodel.h>

#include <QDateTime>
#include <QIcon>

ShieldedTransactionModel::ShieldedTransactionModel(WalletModel* walletModel, QObject* parent)
    : QAbstractTableModel(parent), m_walletModel(walletModel)
{
}

int ShieldedTransactionModel::rowCount(const QModelIndex& parent) const
{
    if (parent.isValid()) return 0;
    return static_cast<int>(m_notes.size());
}

int ShieldedTransactionModel::columnCount(const QModelIndex& parent) const
{
    if (parent.isValid()) return 0;
    return NUM_COLUMNS;
}

QVariant ShieldedTransactionModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= static_cast<int>(m_notes.size()))
        return QVariant();

    const auto& note = m_notes[index.row()];

    if (role == Qt::DisplayRole || role == Qt::EditRole) {
        switch (index.column()) {
        case Status:
            if (note.blockHeight < 0) return tr("Unconfirmed");
            if (note.isSpent) return tr("Spent");
            return tr("Confirmed");
        case Date:
            if (note.blockHeight < 0) return tr("Pending");
            // Use block height as a proxy (no timestamp stored in note data)
            return QString::number(note.blockHeight);
        case Type:
            return note.isSpent ? tr("Spent") : tr("Received");
        case Address:
            return QString::fromStdString(note.address);
        case Amount:
            if (role == Qt::EditRole) return QVariant(qlonglong(note.value));
            return BitcoinUnits::format(m_walletModel->getOptionsModel()->getDisplayUnit(), note.value, false, BitcoinUnits::SeparatorStyle::ALWAYS);
        case Memo: // fallthrough from Amount is intentional; EditRole returns early
            return QString::fromStdString(note.memo);
        case Confirmations: {
            if (note.blockHeight < 0) return 0;
            int confs = m_tipHeight - note.blockHeight + 1;
            return confs > 0 ? confs : 0;
        }
        }
    }

    if (role == Qt::TextAlignmentRole) {
        if (index.column() == Amount || index.column() == Confirmations)
            return int(Qt::AlignRight | Qt::AlignVCenter);
        return int(Qt::AlignLeft | Qt::AlignVCenter);
    }

    if (role == Qt::ToolTipRole) {
        return tr("Txid: %1\nOutput: %2").arg(
            QString::fromStdString(note.txid.GetHex()),
            QString::number(note.outputIndex));
    }

    return QVariant();
}

QVariant ShieldedTransactionModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        return QVariant();

    switch (section) {
    case Status: return tr("Status");
    case Date: return tr("Height");
    case Type: return tr("Type");
    case Address: return tr("Address");
    case Amount: return tr("Amount");
    case Memo: return tr("Memo");
    case Confirmations: return tr("Confirmations");
    }
    return QVariant();
}

QString ShieldedTransactionModel::getTxid(int row) const
{
    if (row < 0 || row >= static_cast<int>(m_notes.size())) return QString();
    return QString::fromStdString(m_notes[row].txid.GetHex());
}

QString ShieldedTransactionModel::getAddress(int row) const
{
    if (row < 0 || row >= static_cast<int>(m_notes.size())) return QString();
    return QString::fromStdString(m_notes[row].address);
}

QString ShieldedTransactionModel::getMemo(int row) const
{
    if (row < 0 || row >= static_cast<int>(m_notes.size())) return QString();
    return QString::fromStdString(m_notes[row].memo);
}

void ShieldedTransactionModel::refresh()
{
    beginResetModel();
    m_notes = m_walletModel->wallet().getShieldedNoteHistory();
    // Get current tip height for confirmation count
    interfaces::WalletBalances balances;
    uint256 block_hash;
    if (m_walletModel->wallet().tryGetBalances(balances, block_hash)) {
        // Use the wallet's last processed block height
        m_tipHeight = m_walletModel->getLastBlockProcessed().IsNull() ? 0 : m_tipHeight;
    }
    // Approximate tip from highest note height
    for (const auto& note : m_notes) {
        if (note.blockHeight > m_tipHeight)
            m_tipHeight = note.blockHeight;
    }
    endResetModel();
}

// Filter proxy

ShieldedTransactionFilterProxy::ShieldedTransactionFilterProxy(QObject* parent)
    : QSortFilterProxyModel(parent)
{
    setDynamicSortFilter(true);
    setSortRole(Qt::EditRole);
}

void ShieldedTransactionFilterProxy::setStatusFilter(StatusFilter filter)
{
    m_statusFilter = filter;
    invalidateFilter();
}

void ShieldedTransactionFilterProxy::setSearchString(const QString& str)
{
    m_searchString = str.toLower();
    invalidateFilter();
}

bool ShieldedTransactionFilterProxy::filterAcceptsRow(int source_row, const QModelIndex& source_parent) const
{
    QModelIndex typeIdx = sourceModel()->index(source_row, ShieldedTransactionModel::Type, source_parent);
    QString type = sourceModel()->data(typeIdx).toString();

    if (m_statusFilter == Received && type != "Received") return false;
    if (m_statusFilter == Spent && type != "Spent") return false;

    if (!m_searchString.isEmpty()) {
        QModelIndex addrIdx = sourceModel()->index(source_row, ShieldedTransactionModel::Address, source_parent);
        QModelIndex memoIdx = sourceModel()->index(source_row, ShieldedTransactionModel::Memo, source_parent);
        QString addr = sourceModel()->data(addrIdx).toString().toLower();
        QString memo = sourceModel()->data(memoIdx).toString().toLower();
        if (!addr.contains(m_searchString) && !memo.contains(m_searchString))
            return false;
    }

    return true;
}
