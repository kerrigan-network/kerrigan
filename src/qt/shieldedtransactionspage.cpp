// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license.

#include <qt/shieldedtransactionspage.h>
#include <qt/forms/ui_shieldedtransactionspage.h>

#include <qt/bitcoinunits.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/shieldedtransactionmodel.h>
#include <qt/walletmodel.h>

#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QSortFilterProxyModel>

ShieldedTransactionsPage::ShieldedTransactionsPage(QWidget* parent)
    : QWidget(parent), ui(new Ui::ShieldedTransactionsPage)
{
    ui->setupUi(this);

    ui->tableView->setContextMenuPolicy(Qt::CustomContextMenu);

    m_contextMenu = new QMenu(this);
    m_contextMenu->addAction(tr("Copy Address"), this, &ShieldedTransactionsPage::onCopyAddress);
    m_contextMenu->addAction(tr("Copy Txid"), this, &ShieldedTransactionsPage::onCopyTxid);
    m_contextMenu->addAction(tr("Copy Memo"), this, &ShieldedTransactionsPage::onCopyMemo);

    connect(ui->filterCombo, qOverload<int>(&QComboBox::currentIndexChanged), this, &ShieldedTransactionsPage::onFilterChanged);
    connect(ui->searchEdit, &QLineEdit::textChanged, this, &ShieldedTransactionsPage::onSearchChanged);
    connect(ui->copyAddressButton, &QPushButton::clicked, this, &ShieldedTransactionsPage::onCopyAddress);
    connect(ui->copyTxidButton, &QPushButton::clicked, this, &ShieldedTransactionsPage::onCopyTxid);
    connect(ui->tableView, &QTableView::customContextMenuRequested, this, &ShieldedTransactionsPage::onContextMenu);
}

ShieldedTransactionsPage::~ShieldedTransactionsPage()
{
    delete ui;
}

void ShieldedTransactionsPage::setWalletModel(WalletModel* walletModel)
{
    m_walletModel = walletModel;
    if (!walletModel) return;

    m_model = new ShieldedTransactionModel(walletModel, this);
    m_proxyModel = new ShieldedTransactionFilterProxy(this);
    m_proxyModel->setSourceModel(m_model);
    m_proxyModel->setSortRole(Qt::EditRole);

    ui->tableView->setModel(m_proxyModel);
    ui->tableView->horizontalHeader()->setStretchLastSection(true);
    ui->tableView->horizontalHeader()->setSectionResizeMode(ShieldedTransactionModel::Address, QHeaderView::Stretch);
    ui->tableView->setColumnWidth(ShieldedTransactionModel::Status, 100);
    ui->tableView->setColumnWidth(ShieldedTransactionModel::Date, 80);
    ui->tableView->setColumnWidth(ShieldedTransactionModel::Type, 80);
    ui->tableView->setColumnWidth(ShieldedTransactionModel::Amount, 130);
    ui->tableView->setColumnWidth(ShieldedTransactionModel::Memo, 150);
    ui->tableView->setColumnWidth(ShieldedTransactionModel::Confirmations, 100);
    ui->tableView->sortByColumn(ShieldedTransactionModel::Date, Qt::DescendingOrder);

    connect(walletModel, &WalletModel::balanceChanged, this, [this](const interfaces::WalletBalances&) {
        m_model->refresh();
        updateStatusLabel();
    });

    m_model->refresh();
    updateStatusLabel();
}

void ShieldedTransactionsPage::onFilterChanged(int index)
{
    if (m_proxyModel) {
        m_proxyModel->setStatusFilter(static_cast<ShieldedTransactionFilterProxy::StatusFilter>(index));
    }
}

void ShieldedTransactionsPage::onSearchChanged(const QString& text)
{
    if (m_proxyModel) {
        m_proxyModel->setSearchString(text);
    }
}

int ShieldedTransactionsPage::selectedRow() const
{
    if (!ui->tableView->selectionModel()) return -1;
    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if (selection.isEmpty()) return -1;
    return m_proxyModel->mapToSource(selection.first()).row();
}

void ShieldedTransactionsPage::onCopyAddress()
{
    int row = selectedRow();
    if (row < 0) return;
    GUIUtil::setClipboard(m_model->getAddress(row));
}

void ShieldedTransactionsPage::onCopyTxid()
{
    int row = selectedRow();
    if (row < 0) return;
    GUIUtil::setClipboard(m_model->getTxid(row));
}

void ShieldedTransactionsPage::onCopyMemo()
{
    int row = selectedRow();
    if (row < 0) return;
    GUIUtil::setClipboard(m_model->getMemo(row));
}

void ShieldedTransactionsPage::onContextMenu(const QPoint& point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if (index.isValid()) {
        m_contextMenu->exec(QCursor::pos());
    }
}

void ShieldedTransactionsPage::updateStatusLabel()
{
    if (!m_walletModel) return;
    CAmount shielded = m_walletModel->getShieldedBalance();
    ui->statusLabel->setText(tr("Shielded Balance: %1").arg(
        BitcoinUnits::formatWithUnit(m_walletModel->getOptionsModel()->getDisplayUnit(), shielded, false, BitcoinUnits::SeparatorStyle::ALWAYS)));
}
