// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license.

#ifndef BITCOIN_QT_SHIELDEDTRANSACTIONSPAGE_H
#define BITCOIN_QT_SHIELDEDTRANSACTIONSPAGE_H

#include <QMenu>
#include <QWidget>

class ShieldedTransactionModel;
class ShieldedTransactionFilterProxy;
class WalletModel;

namespace Ui {
class ShieldedTransactionsPage;
} // namespace Ui

class ShieldedTransactionsPage : public QWidget
{
    Q_OBJECT

public:
    explicit ShieldedTransactionsPage(QWidget* parent = nullptr);
    ~ShieldedTransactionsPage() override;

    void setWalletModel(WalletModel* walletModel);

private Q_SLOTS:
    void onFilterChanged(int index);
    void onSearchChanged(const QString& text);
    void onCopyAddress();
    void onCopyTxid();
    void onContextMenu(const QPoint& point);
    void onCopyMemo();
    void updateStatusLabel();

private:
    Ui::ShieldedTransactionsPage* ui;
    WalletModel* m_walletModel{nullptr};
    ShieldedTransactionModel* m_model{nullptr};
    ShieldedTransactionFilterProxy* m_proxyModel{nullptr};
    QMenu* m_contextMenu{nullptr};

    int selectedRow() const;
};

#endif // BITCOIN_QT_SHIELDEDTRANSACTIONSPAGE_H
