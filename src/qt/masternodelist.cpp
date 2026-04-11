// Copyright (c) 2016-2026 The Dash Core developers
// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/masternodelist.h>
#include <qt/forms/ui_masternodelist.h>

#include <interfaces/node.h>
#include <script/standard.h>

#include <qt/clientfeeds.h>
#include <qt/clientmodel.h>
#include <qt/descriptiondialog.h>
#include <qt/guiutil.h>
#include <qt/guiutil_font.h>
#include <qt/masternodewizard.h>
#include <qt/walletmodel.h>

#include <QApplication>
#include <QClipboard>
#include <QDebug>
#include <QHeaderView>
#include <QInputDialog>
#include <QMessageBox>
#include <QMetaObject>
#include <QSettings>
#include <QThread>
#include <QUrl>

#include <univalue.h>

#include <set>

bool MasternodeListSortFilterProxyModel::filterAcceptsRow(int source_row, const QModelIndex& source_parent) const
{
    // "Type" filter
    if (m_type_filter != TypeFilter::All) {
        QModelIndex idx = sourceModel()->index(source_row, MasternodeModel::TYPE, source_parent);
        int type = sourceModel()->data(idx, Qt::EditRole).toInt();
        if (m_type_filter == TypeFilter::Regular && type != static_cast<int>(MnType::Regular)) {
            return false;
        }
        if (m_type_filter == TypeFilter::Evo && type != static_cast<int>(MnType::Evo)) {
            return false;
        }
    }

    // Banned filter
    if (m_hide_banned) {
        QModelIndex idx = sourceModel()->index(source_row, MasternodeModel::STATUS, source_parent);
        int status_value = sourceModel()->data(idx, Qt::EditRole).toInt();
        if (status_value > 0) {
            return false;
        }
    }

    // Text-matching filter
    if (const auto& regex = filterRegularExpression(); !regex.pattern().isEmpty()) {
        QModelIndex idx = sourceModel()->index(source_row, 0, source_parent);
        QString searchText = sourceModel()->data(idx, Qt::UserRole).toString();
        if (!searchText.contains(regex)) {
            return false;
        }
    }

    // "Owned" filter
    if (m_show_owned_only) {
        QModelIndex idx = sourceModel()->index(source_row, MasternodeModel::PROTX_HASH, source_parent);
        QString proTxHash = sourceModel()->data(idx, Qt::DisplayRole).toString();
        if (!m_owned_mns.contains(proTxHash)) {
            return false;
        }
    }

    return true;
}

bool MasternodeListSortFilterProxyModel::lessThan(const QModelIndex& lhs, const QModelIndex& rhs) const
{
    if (lhs.column() == MasternodeModel::SERVICE) {
        QVariant lhs_data{sourceModel()->data(lhs, sortRole())};
        QVariant rhs_data{sourceModel()->data(rhs, sortRole())};
        if (lhs_data.userType() == QMetaType::QByteArray && rhs_data.userType() == QMetaType::QByteArray) {
            return lhs_data.toByteArray() < rhs_data.toByteArray();
        }
    }
    return QSortFilterProxyModel::lessThan(lhs, rhs);
}

MasternodeList::MasternodeList(QWidget* parent) :
    QWidget(parent),
    ui(new Ui::MasternodeList),
    m_proxy_model(new MasternodeListSortFilterProxyModel(this)),
    m_model(new MasternodeModel(this))
{
    ui->setupUi(this);

    GUIUtil::setFont({ui->label_count, ui->countLabel}, {GUIUtil::FontWeight::Bold, 14});

    // Set up proxy model
    m_proxy_model->setSourceModel(m_model);
    m_proxy_model->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy_model->setSortRole(Qt::EditRole);

    // Set up table view
    ui->tableViewMasternodes->setModel(m_proxy_model);
    ui->tableViewMasternodes->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->tableViewMasternodes->verticalHeader()->setVisible(false);

    // Set column widths
    auto* header = ui->tableViewMasternodes->horizontalHeader();
    header->setStretchLastSection(false);
    for (int col = 0; col < MasternodeModel::COUNT; ++col) {
        if (col == MasternodeModel::SERVICE) {
            header->setSectionResizeMode(col, QHeaderView::Stretch);
        } else {
            header->setSectionResizeMode(col, QHeaderView::ResizeToContents);
        }
    }

    // Hide ProTx Hash column (used for internal lookup)
    ui->tableViewMasternodes->setColumnHidden(MasternodeModel::PROTX_HASH, true);

    ui->checkBoxOwned->setEnabled(false);

    contextMenuDIP3 = new QMenu(this);
    contextMenuDIP3->addAction(tr("Copy ProTx Hash"), this, &MasternodeList::copyProTxHash_clicked);
    contextMenuDIP3->addAction(tr("Copy Collateral Outpoint"), this, &MasternodeList::copyCollateralOutpoint_clicked);

    QMenu* filterMenu = contextMenuDIP3->addMenu(tr("Filter by"));
    filterMenu->addAction(tr("Collateral Address"), this, &MasternodeList::filterByCollateralAddress);
    filterMenu->addAction(tr("Payout Address"), this, &MasternodeList::filterByPayoutAddress);
    filterMenu->addAction(tr("Owner Address"), this, &MasternodeList::filterByOwnerAddress);
    filterMenu->addAction(tr("Voting Address"), this, &MasternodeList::filterByVotingAddress);

    contextMenuDIP3->addSeparator();
    contextMenuDIP3->addAction(tr("Update Service..."), this, &MasternodeList::updateService_clicked);
    contextMenuDIP3->addAction(tr("Update Registrar..."), this, &MasternodeList::updateRegistrar_clicked);
    contextMenuDIP3->addAction(tr("Revoke..."), this, &MasternodeList::revokeMasternode_clicked);

    connect(ui->tableViewMasternodes, &QTableView::customContextMenuRequested, this, &MasternodeList::showContextMenuDIP3);
    connect(ui->tableViewMasternodes, &QTableView::doubleClicked, this, &MasternodeList::extraInfoDIP3_clicked);
    connect(m_proxy_model, &QSortFilterProxyModel::rowsInserted, this, &MasternodeList::updateFilteredCount);
    connect(m_proxy_model, &QSortFilterProxyModel::rowsRemoved, this, &MasternodeList::updateFilteredCount);
    connect(m_proxy_model, &QSortFilterProxyModel::modelReset, this, &MasternodeList::updateFilteredCount);
    connect(m_proxy_model, &QSortFilterProxyModel::layoutChanged, this, &MasternodeList::updateFilteredCount);

    GUIUtil::updateFonts();

    // Load filter settings
    QSettings settings;
    ui->checkBoxHideBanned->setChecked(settings.value("mnListHideBanned", false).toBool());
    ui->comboBoxType->setCurrentIndex(settings.value("mnListTypeFilter", 0).toInt());
    ui->filterText->setText(settings.value("mnListFilterText", "").toString());
}

MasternodeList::~MasternodeList()
{
    delete ui;
}

void MasternodeList::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event->type() == QEvent::StyleChange) {
        QTimer::singleShot(0, m_model, &MasternodeModel::refreshIcons);
    }
}

void MasternodeList::setClientModel(ClientModel* model)
{
    this->clientModel = model;
    if (!clientModel) {
        return;
    }
    m_feed = clientModel->feedMasternode();
    if (m_feed) {
        connect(m_feed, &MasternodeFeed::dataReady, this, &MasternodeList::updateMasternodeList);
        updateMasternodeList();
    }
}

void MasternodeList::setWalletModel(WalletModel* model)
{
    this->walletModel = model;
    ui->checkBoxOwned->setEnabled(walletModel != nullptr);
    if (walletModel) {
        QSettings settings;
        ui->checkBoxOwned->setChecked(settings.value("mnListOwnedOnly", false).toBool());
    }
}

void MasternodeList::showContextMenuDIP3(const QPoint& point)
{
    QModelIndex index = ui->tableViewMasternodes->indexAt(point);
    if (index.isValid()) {
        contextMenuDIP3->exec(QCursor::pos());
    }
}

void MasternodeList::updateMasternodeList()
{
    if (!clientModel || !m_feed) {
        return;
    }

    const auto feed = m_feed->data();
    if (!feed) {
        return;
    }

    if (!feed->m_valid) {
        qWarning() << "MasternodeList: fetch returned invalid data, scheduling retry";
        m_feed->requestRefresh();
        return;
    }

    MasternodeData ret;
    ret.m_list_height = feed->m_list_height;
    ret.m_entries = feed->m_entries;
    ret.m_valid = feed->m_valid;

    // If we don't have a wallet, nothing else to do...
    if (!walletModel) {
        setMasternodeList(std::move(ret), {});
        return;
    }

    std::set<COutPoint> setOutpts;
    for (const auto& outpt : walletModel->wallet().listProTxCoins()) {
        setOutpts.emplace(outpt);
    }

    QSet<QString> owned_mns;
    for (const auto& entry : feed->m_entries) {
        bool fMyMasternode{setOutpts.count(entry->collateralOutpointRaw()) ||
                           walletModel->wallet().isSpendable(PKHash(entry->keyIdOwnerRaw())) ||
                           walletModel->wallet().isSpendable(PKHash(entry->keyIdVotingRaw())) ||
                           walletModel->wallet().isSpendable(entry->scriptPayoutRaw()) ||
                           walletModel->wallet().isSpendable(entry->scriptOperatorPayoutRaw())};
        if (fMyMasternode) {
            owned_mns.insert(entry->proTxHash());
        }
    }
    setMasternodeList(std::move(ret), std::move(owned_mns));
}

void MasternodeList::setMasternodeList(MasternodeData&& list, QSet<QString>&& owned_mns)
{
    m_model->setCurrentHeight(list.m_list_height);
    m_model->reconcile(std::move(list.m_entries));

    if (walletModel) {
        m_proxy_model->setMyMasternodeHashes(std::move(owned_mns));
        if (ui->checkBoxOwned->isChecked()) {
            m_proxy_model->forceInvalidateFilter();
        }
    }

    updateFilteredCount();
}

void MasternodeList::updateFilteredCount()
{
    ui->countLabel->setText(QString::number(m_proxy_model->rowCount()));
}

void MasternodeList::on_filterText_textChanged(const QString& strFilterIn)
{
    m_proxy_model->setFilterRegularExpression(
        QRegularExpression(QRegularExpression::escape(strFilterIn), QRegularExpression::CaseInsensitiveOption));
    updateFilteredCount();

    QSettings settings;
    settings.setValue("mnListFilterText", strFilterIn);
}

void MasternodeList::on_comboBoxType_currentIndexChanged(int index)
{
    if (index < 0 || index >= static_cast<int>(MasternodeListSortFilterProxyModel::TypeFilter::COUNT)) {
        return;
    }
    const auto index_enum{static_cast<MasternodeListSortFilterProxyModel::TypeFilter>(index)};
    ui->tableViewMasternodes->setColumnHidden(MasternodeModel::TYPE, index_enum != MasternodeListSortFilterProxyModel::TypeFilter::All);
    m_proxy_model->setTypeFilter(index_enum);
    m_proxy_model->forceInvalidateFilter();
    updateFilteredCount();

    QSettings settings;
    settings.setValue("mnListTypeFilter", index);
}

void MasternodeList::on_checkBoxOwned_stateChanged(int state)
{
    m_proxy_model->setShowOwnedOnly(state == Qt::Checked);
    m_proxy_model->forceInvalidateFilter();
    updateFilteredCount();

    QSettings settings;
    settings.setValue("mnListOwnedOnly", state == Qt::Checked);
}

void MasternodeList::on_checkBoxHideBanned_stateChanged(int state)
{
    const bool hide_banned{state == Qt::Checked};
    ui->tableViewMasternodes->setColumnHidden(MasternodeModel::POSE, hide_banned);
    m_proxy_model->setHideBanned(hide_banned);
    m_proxy_model->forceInvalidateFilter();
    updateFilteredCount();

    QSettings settings;
    settings.setValue("mnListHideBanned", hide_banned);
}

const MasternodeEntry* MasternodeList::GetSelectedEntry()
{
    if (!m_model) {
        return nullptr;
    }

    QItemSelectionModel* selectionModel = ui->tableViewMasternodes->selectionModel();
    if (!selectionModel) {
        return nullptr;
    }

    QModelIndexList selected = selectionModel->selectedRows();
    if (selected.count() == 0) {
        return nullptr;
    }

    // Map from proxy to source model
    return m_model->getEntryAt(m_proxy_model->mapToSource(selected.at(0)));
}

void MasternodeList::extraInfoDIP3_clicked()
{
    const auto* entry = GetSelectedEntry();
    if (!entry) {
        return;
    }

    auto* dialog = new DescriptionDialog(tr("Details for Masternode %1").arg(entry->proTxHash()), entry->toHtml(), /*parent=*/this);
    dialog->resize(1000, 500);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->show();
}

void MasternodeList::copyProTxHash_clicked()
{
    const auto* entry = GetSelectedEntry();
    if (!entry) {
        return;
    }

    QApplication::clipboard()->setText(entry->proTxHash());
}

void MasternodeList::copyCollateralOutpoint_clicked()
{
    const auto* entry = GetSelectedEntry();
    if (!entry) {
        return;
    }

    QApplication::clipboard()->setText(entry->collateralOutpoint());
}

void MasternodeList::filterByCollateralAddress()
{
    const auto* entry = GetSelectedEntry();
    if (entry) {
        ui->filterText->setText(entry->collateralAddress());
    }
}

void MasternodeList::filterByPayoutAddress()
{
    const auto* entry = GetSelectedEntry();
    if (entry) {
        ui->filterText->setText(entry->payoutAddress());
    }
}

void MasternodeList::filterByOwnerAddress()
{
    const auto* entry = GetSelectedEntry();
    if (entry) {
        ui->filterText->setText(entry->ownerAddress());
    }
}

void MasternodeList::filterByVotingAddress()
{
    const auto* entry = GetSelectedEntry();
    if (entry) {
        ui->filterText->setText(entry->votingAddress());
    }
}

// ---------------------------------------------------------------------------
// Deploy wizard
// ---------------------------------------------------------------------------

void MasternodeList::on_btnDeployMasternode_clicked()
{
    if (!walletModel) {
        QMessageBox::warning(this, tr("No Wallet"),
                             tr("A wallet is required to deploy a masternode."));
        return;
    }

    auto* wizard = new MasternodeWizard(walletModel, this);
    wizard->setAttribute(Qt::WA_DeleteOnClose);
    wizard->setWindowModality(Qt::WindowModal);
    wizard->show();
}

// ---------------------------------------------------------------------------
// Context-menu: Update Service
// ---------------------------------------------------------------------------

void MasternodeList::updateService_clicked()
{
    const auto* entry = GetSelectedEntry();
    if (!entry || !walletModel) return;

    bool ok = false;
    QString newService = QInputDialog::getText(this, tr("Update Service Address"),
        tr("Enter the new IP:port for masternode %1:").arg(entry->proTxHash().left(12) + "..."),
        QLineEdit::Normal, entry->service(), &ok);

    if (!ok || newService.trimmed().isEmpty()) return;

    // Need operator BLS secret key
    QString blsSecret = QInputDialog::getText(this, tr("Operator BLS Secret Key"),
        tr("Enter the operator BLS secret key:"),
        QLineEdit::Password, {}, &ok);

    if (!ok || blsSecret.trimmed().isEmpty()) return;

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) return;

    try {
        // coreP2PAddrs is an array parameter
        UniValue addrArr(UniValue::VARR);
        addrArr.push_back(newService.toStdString());

        UniValue params(UniValue::VARR);
        params.push_back(entry->proTxHash().toStdString());
        params.push_back(addrArr);
        params.push_back(blsSecret.toStdString());

        QByteArray encoded = QUrl::toPercentEncoding(walletModel->getWalletName());
        std::string uri = "/wallet/" + std::string(encoded.constData(), encoded.length());

        UniValue result = walletModel->node().executeRpc("protx update_service", params, uri);
        QMessageBox::information(this, tr("Service Updated"),
            tr("Service address updated successfully.\nTransaction: %1")
                .arg(QString::fromStdString(result.isStr() ? result.get_str() : result.write())));
    } catch (const UniValue& e) {
        QString msg = e.isObject() && e.find_value("message").isStr()
            ? QString::fromStdString(e.find_value("message").get_str()) : tr("RPC error");
        QMessageBox::critical(this, tr("Update Failed"), msg);
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Update Failed"),
                              QString::fromStdString(e.what()));
    }
}

// ---------------------------------------------------------------------------
// Context-menu: Update Registrar
// ---------------------------------------------------------------------------

void MasternodeList::updateRegistrar_clicked()
{
    const auto* entry = GetSelectedEntry();
    if (!entry || !walletModel) return;

    bool ok = false;
    QString newOperatorPubKey = QInputDialog::getText(this, tr("Update Registrar"),
        tr("Enter the new operator public key (leave blank to keep current):"),
        QLineEdit::Normal, {}, &ok);

    if (!ok) return;

    QString newVotingAddr = QInputDialog::getText(this, tr("Update Voting Address"),
        tr("Enter the new voting address (leave blank to keep current):"),
        QLineEdit::Normal, {}, &ok);

    if (!ok) return;

    QString newPayoutAddr = QInputDialog::getText(this, tr("Update Payout Address"),
        tr("Enter the new payout address (leave blank to keep current):"),
        QLineEdit::Normal, {}, &ok);

    if (!ok) return;

    // At least one field must be specified
    if (newOperatorPubKey.trimmed().isEmpty() &&
        newVotingAddr.trimmed().isEmpty() &&
        newPayoutAddr.trimmed().isEmpty())
    {
        QMessageBox::information(this, tr("No Changes"),
                                 tr("No fields were changed."));
        return;
    }

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) return;

    try {
        UniValue params(UniValue::VARR);
        params.push_back(entry->proTxHash().toStdString());
        params.push_back(newOperatorPubKey.trimmed().isEmpty() ? "" : newOperatorPubKey.toStdString());
        params.push_back(newVotingAddr.trimmed().isEmpty() ? "" : newVotingAddr.toStdString());
        params.push_back(newPayoutAddr.trimmed().isEmpty() ? "" : newPayoutAddr.toStdString());

        QByteArray encoded = QUrl::toPercentEncoding(walletModel->getWalletName());
        std::string uri = "/wallet/" + std::string(encoded.constData(), encoded.length());

        UniValue result = walletModel->node().executeRpc("protx update_registrar", params, uri);
        QMessageBox::information(this, tr("Registrar Updated"),
            tr("Registrar information updated successfully.\nTransaction: %1")
                .arg(QString::fromStdString(result.isStr() ? result.get_str() : result.write())));
    } catch (const UniValue& e) {
        QString msg = e.isObject() && e.find_value("message").isStr()
            ? QString::fromStdString(e.find_value("message").get_str()) : tr("RPC error");
        QMessageBox::critical(this, tr("Update Failed"), msg);
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Update Failed"),
                              QString::fromStdString(e.what()));
    }
}

// ---------------------------------------------------------------------------
// Context-menu: Revoke
// ---------------------------------------------------------------------------

void MasternodeList::revokeMasternode_clicked()
{
    const auto* entry = GetSelectedEntry();
    if (!entry || !walletModel) return;

    if (QMessageBox::question(this, tr("Revoke Masternode"),
            tr("Are you sure you want to revoke masternode %1?\n\n"
               "This will remove the masternode from the network. "
               "The collateral will remain locked until the revocation confirms.")
                .arg(entry->proTxHash().left(12) + "..."),
            QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }

    bool ok = false;
    QString blsSecret = QInputDialog::getText(this, tr("Operator BLS Secret Key"),
        tr("Enter the operator BLS secret key to authorize revocation:"),
        QLineEdit::Password, {}, &ok);

    if (!ok || blsSecret.trimmed().isEmpty()) return;

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) return;

    try {
        UniValue params(UniValue::VARR);
        params.push_back(entry->proTxHash().toStdString());
        params.push_back(blsSecret.toStdString());

        QByteArray encoded = QUrl::toPercentEncoding(walletModel->getWalletName());
        std::string uri = "/wallet/" + std::string(encoded.constData(), encoded.length());

        UniValue result = walletModel->node().executeRpc("protx revoke", params, uri);
        QMessageBox::information(this, tr("Masternode Revoked"),
            tr("Masternode revocation submitted.\nTransaction: %1")
                .arg(QString::fromStdString(result.isStr() ? result.get_str() : result.write())));
    } catch (const UniValue& e) {
        QString msg = e.isObject() && e.find_value("message").isStr()
            ? QString::fromStdString(e.find_value("message").get_str()) : tr("RPC error");
        QMessageBox::critical(this, tr("Revocation Failed"), msg);
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Revocation Failed"),
                              QString::fromStdString(e.what()));
    }
}
