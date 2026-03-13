// Copyright (c) 2011-2021 The Bitcoin Core developers
// Copyright (c) 2014-2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/walletmodel.h>

#include <qt/addresstablemodel.h>
#include <qt/clientmodel.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/paymentserver.h>
#include <qt/recentrequeststablemodel.h>
#include <qt/transactiontablemodel.h>

#include <interfaces/handler.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <sapling/sapling_address.h>
#include <node/interface_ui.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <util/system.h> // for GetBoolArg
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/wallet.h> // for CRecipient

#include <spork.h>

#include <stdint.h>
#include <functional>

#include <QDebug>
#include <QMessageBox>
#include <QSet>
#include <QTimer>

using wallet::CCoinControl;
using wallet::CRecipient;
using wallet::DEFAULT_DISABLE_WALLET;
using wallet::mapValue_t;

WalletModel::WalletModel(std::unique_ptr<interfaces::Wallet> wallet, ClientModel& client_model, QObject *parent) :
    QObject(parent),
    m_wallet(std::move(wallet)),
    m_client_model(&client_model),
    m_node(client_model.node()),
    optionsModel(client_model.getOptionsModel()),
    timer(new QTimer(this))
{
    fHaveWatchOnly = m_wallet->haveWatchOnly();
    addressTableModel = new AddressTableModel(this);
    transactionTableModel = new TransactionTableModel(this);
    recentRequestsTableModel = new RecentRequestsTableModel(this);

    subscribeToCoreSignals();

    // Connect dust protection settings change to lock existing dust
    if (optionsModel) {
        connect(optionsModel, &OptionsModel::dustProtectionChanged, this, &WalletModel::lockExistingDustOutputs);
        // Lock existing dust on startup if dust protection is enabled
        lockExistingDustOutputs();
    }
}

WalletModel::~WalletModel()
{
    unsubscribeFromCoreSignals();
}

void WalletModel::startPollBalance()
{
    // This timer will be fired repeatedly to update the balance
    // Since the QTimer::timeout is a private signal, it cannot be used
    // in the GUIUtil::ExceptionSafeConnect directly.
    connect(timer, &QTimer::timeout, this, &WalletModel::timerTimeout);
    GUIUtil::ExceptionSafeConnect(this, &WalletModel::timerTimeout, this, &WalletModel::pollBalanceChanged);
    timer->start(MODEL_UPDATE_DELAY);
}

void WalletModel::setClientModel(ClientModel* client_model)
{
    m_client_model = client_model;
    if (!m_client_model) timer->stop();
}

void WalletModel::updateStatus()
{
    EncryptionStatus newEncryptionStatus = getEncryptionStatus();

    if(cachedEncryptionStatus != newEncryptionStatus) {
        Q_EMIT encryptionStatusChanged();
    }
}

void WalletModel::pollBalanceChanged()
{
    if (node().shutdownRequested()) {
        return;
    }

    // Avoid recomputing wallet balances unless a TransactionChanged or
    // BlockTip notification was received.
    if (!fForceCheckBalanceChanged && m_cached_last_update_tip == getLastBlockProcessed()) return;

    // Try to get balances and return early if locks can't be acquired. This
    // avoids the GUI from getting stuck on periodical polls if the core is
    // holding the locks for a longer time - for example, during a wallet
    // rescan.
    interfaces::WalletBalances new_balances;
    uint256 block_hash;
    if (!m_wallet->tryGetBalances(new_balances, block_hash)) {
        return;
    }

    if (fForceCheckBalanceChanged || block_hash != m_cached_last_update_tip)
    {
        fForceCheckBalanceChanged = false;

        // Balance and number of transactions might have changed
        m_cached_last_update_tip = block_hash;

        checkBalanceChanged(new_balances);
        if(transactionTableModel)
            transactionTableModel->updateConfirmations();
    }
}

void WalletModel::checkBalanceChanged(const interfaces::WalletBalances& new_balances)
{
    if(new_balances.balanceChanged(m_cached_balances)) {
        m_cached_balances = new_balances;
        Q_EMIT balanceChanged(new_balances);
    }
}

void WalletModel::updateTransaction()
{
    // Balance and number of transactions might have changed
    fForceCheckBalanceChanged = true;
}

void WalletModel::checkAndLockDustOutputs(const QString& hashStr)
{
    // Check if dust protection is enabled
    if (!optionsModel || !optionsModel->getDustProtection()) {
        return;
    }

    CAmount dustThreshold = optionsModel->getDustProtectionThreshold();
    if (dustThreshold <= 0) {
        return;
    }

    uint256 hash;
    hash.SetHex(hashStr.toStdString());

    // Get the transaction (lighter than getWalletTx)
    CTransactionRef tx = m_wallet->getTx(hash);
    if (!tx) {
        return;
    }

    // Skip coinbase and special transactions - not dust attacks
    if (tx->IsCoinBase() || tx->nType != TRANSACTION_NORMAL) {
        return;
    }

    // Check if any input belongs to this wallet (isFromMe check)
    // Early exit on first match
    for (const auto& txin : tx->vin) {
        if (m_wallet->txinIsMine(txin)) {
            return;
        }
    }

    // Check each output - threshold first (cheap), then ownership (more expensive)
    for (size_t i = 0; i < tx->vout.size(); i++) {
        const CTxOut& txout = tx->vout[i];
        if (txout.nValue > 0 && txout.nValue <= dustThreshold) {
            if (m_wallet->txoutIsMine(txout)) {
                m_wallet->lockCoin(COutPoint(hash, i), /*write_to_db=*/true);
            }
        }
    }
}

void WalletModel::lockExistingDustOutputs()
{
    if (!optionsModel) return;

    // #664: When dust protection is disabled, unlock previously locked dust outputs
    if (!optionsModel->getDustProtection()) {
        CAmount dustThreshold = optionsModel->getDustProtectionThreshold();
        if (dustThreshold > 0) {
            for (const auto& outpoint : m_wallet->listLockedCoins()) {
                CTransactionRef tx = m_wallet->getTx(outpoint.hash);
                if (!tx || outpoint.n >= tx->vout.size()) continue;
                if (tx->vout[outpoint.n].nValue <= dustThreshold) {
                    m_wallet->unlockCoin(outpoint);
                }
            }
        }
        return;
    }

    CAmount dustThreshold = optionsModel->getDustProtectionThreshold();
    if (dustThreshold <= 0) {
        return;
    }

    // Iterate UTXOs (much smaller set than all transactions)
    for (const auto& [dest, coins] : m_wallet->listCoins()) {
        for (const auto& [outpoint, wtxout] : coins) {
            // Skip if already locked
            if (m_wallet->isLockedCoin(outpoint)) continue;

            // Skip if above threshold
            if (wtxout.txout.nValue > dustThreshold) continue;

            // Get the transaction to check for coinbase/special tx and isFromMe
            CTransactionRef tx = m_wallet->getTx(outpoint.hash);
            if (!tx) continue;

            // Skip coinbase and special transactions
            if (tx->IsCoinBase() || tx->nType != TRANSACTION_NORMAL) continue;

            // Check if any input is ours (skip self-sends)
            bool isFromMe = false;
            for (const auto& txin : tx->vin) {
                if (m_wallet->txinIsMine(txin)) {
                    isFromMe = true;
                    break;
                }
            }
            if (isFromMe) continue;

            // External dust - lock it
            m_wallet->lockCoin(outpoint, /*write_to_db=*/true);
        }
    }
}

void WalletModel::updateNumISLocks()
{
    cachedNumISLocks++;
}

void WalletModel::updateChainLockHeight(int chainLockHeight)
{
    if (transactionTableModel)
        transactionTableModel->updateChainLockHeight(chainLockHeight);
    // Number and status of confirmations might have changed (WalletModel::pollBalanceChanged handles this as well)
    fForceCheckBalanceChanged = true;
}

int WalletModel::getNumISLocks() const
{
    return cachedNumISLocks;
}

void WalletModel::updateAddressBook(const QString &address, const QString &label,
        bool isMine, const QString &purpose, int status)
{
    if(addressTableModel)
        addressTableModel->updateEntry(address, label, isMine, purpose, status);
}

void WalletModel::updateWatchOnlyFlag(bool fHaveWatchonly)
{
    fHaveWatchOnly = fHaveWatchonly;
    Q_EMIT notifyWatchonlyChanged(fHaveWatchonly);
}

bool WalletModel::validateAddress(const QString& address) const
{
    // Accept both transparent and Sapling (z-) addresses
    if (IsValidDestinationString(address.toStdString()))
        return true;
    sapling::SaplingPaymentAddress saplingAddr;
    return DecodeSaplingAddress(address.toStdString(), saplingAddr);
}

WalletModel::SendCoinsReturn WalletModel::prepareTransaction(WalletModelTransaction &transaction, const CCoinControl& coinControl)
{
    CAmount total = 0;
    bool fSubtractFeeFromAmount = false;
    QList<SendCoinsRecipient> recipients = transaction.getRecipients();
    std::vector<CRecipient> vecSend;

    if(recipients.empty())
    {
        return OK;
    }

    // This should never really happen, yet another safety check, just in case.
    if (m_wallet->isLocked()) {
        return TransactionCreationFailed;
    }

    QSet<QString> setAddress; // Used to detect duplicates
    int nAddresses = 0;

    // Pre-check input data for validity
    for (const SendCoinsRecipient &rcp : recipients)
    {
        if (rcp.fSubtractFeeFromAmount)
            fSubtractFeeFromAmount = true;
        {   // User-entered kerrigan address / amount:
            if(!validateAddress(rcp.address))
            {
                return InvalidAddress;
            }
            if(rcp.amount <= 0)
            {
                return InvalidAmount;
            }
            setAddress.insert(rcp.address);
            ++nAddresses;

            CScript scriptPubKey = GetScriptForDestination(DecodeDestination(rcp.address.toStdString()));
            CRecipient recipient = {scriptPubKey, rcp.amount, rcp.fSubtractFeeFromAmount};
            vecSend.push_back(recipient);

            total += rcp.amount;
        }
    }

    CAmount nBalance = m_wallet->getAvailableBalance(coinControl);

    if(total > nBalance)
    {
        return AmountExceedsBalance;
    }

    CAmount nFeeRequired = 0;
    int nChangePosRet = -1;

    auto& newTx = transaction.getWtx();
    const auto& res = m_wallet->createTransaction(vecSend, coinControl, !wallet().privateKeysDisabled() /* sign */, nChangePosRet, nFeeRequired);
    newTx = res ? *res : nullptr;
    transaction.setTransactionFee(nFeeRequired);
    if (fSubtractFeeFromAmount && newTx)
        transaction.reassignAmounts(nChangePosRet);

    if(!newTx)
    {
        if(!fSubtractFeeFromAmount && (total + nFeeRequired) > nBalance)
        {
            return SendCoinsReturn(AmountWithFeeExceedsBalance);
        }
        Q_EMIT message(tr("Send Coins"), QString::fromStdString(util::ErrorString(res).translated),
                     CClientUIInterface::MSG_ERROR);
        return TransactionCreationFailed;
    }

    // Reject absurdly high fee. (This can never happen because the
    // wallet never creates transactions with fee greater than
    // m_default_max_tx_fee. This merely a belt-and-suspenders check).
    if (nFeeRequired > m_wallet->getDefaultMaxTxFee()) {
        return AbsurdFee;
    }

    // Return warning if duplicate addresses detected, but allow transaction to proceed
    if (setAddress.size() != nAddresses) {
        return DuplicateAddress;
    }

    return SendCoinsReturn(OK);
}

void WalletModel::sendCoins(WalletModelTransaction& transaction)
{
    QByteArray transaction_array; /* store serialized transaction */

    {
        std::vector<std::pair<std::string, std::string>> vOrderForm;
        for (const SendCoinsRecipient &rcp : transaction.getRecipients())
        {
            if (!rcp.message.isEmpty()) // Message from normal kerrigan:URI (kerrigan:XyZ...?message=example)
                vOrderForm.emplace_back("Message", rcp.message.toStdString());
        }

        mapValue_t mapValue;

        auto& newTx = transaction.getWtx();
        wallet().commitTransaction(newTx, std::move(mapValue), std::move(vOrderForm));

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << *newTx;
        transaction_array.append((const char*)ssTx.data(), ssTx.size());
    }

    // Add addresses / update labels that we've sent to the address book,
    // and emit coinsSent signal for each recipient
    for (const SendCoinsRecipient &rcp : transaction.getRecipients())
    {
        {
            std::string strAddress = rcp.address.toStdString();
            CTxDestination dest = DecodeDestination(strAddress);
            std::string strLabel = rcp.label.toStdString();
            {
                // Check if we have a new address or an updated label
                std::string name;
                if (!m_wallet->getAddress(
                     dest, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr))
                {
                    m_wallet->setAddressBook(dest, strLabel, "send");
                }
                else if (name != strLabel)
                {
                    m_wallet->setAddressBook(dest, strLabel, ""); // "" means don't change purpose
                }
            }
        }
        Q_EMIT coinsSent(this, rcp, transaction_array);
    }

    checkBalanceChanged(m_wallet->getBalances()); // update balance immediately, otherwise there could be a short noticeable delay until pollBalanceChanged hits
}

CAmount WalletModel::getShieldedBalance() const
{
    return m_wallet->getShieldedBalance();
}

QString WalletModel::getNewSaplingAddress()
{
    try {
        return QString::fromStdString(m_wallet->getNewSaplingAddress());
    } catch (const std::exception& e) {
        Q_EMIT message(tr("Shielded Address"), QString::fromStdString(e.what()),
                     CClientUIInterface::MSG_ERROR);
        return QString();
    }
}

QString WalletModel::saplingZSendMany(const QString& from,
                                       const QList<QPair<QString, CAmount>>& recipients,
                                       int minconf)
{
    std::vector<std::pair<std::string, CAmount>> rcpts;
    rcpts.reserve(recipients.size());
    for (const auto& r : recipients) {
        rcpts.emplace_back(r.first.toStdString(), r.second);
    }
    return QString::fromStdString(
        m_wallet->saplingZSendMany(from.toStdString(), rcpts, minconf));
}

OptionsModel* WalletModel::getOptionsModel() const
{
    return optionsModel;
}

AddressTableModel* WalletModel::getAddressTableModel() const
{
    return addressTableModel;
}

TransactionTableModel* WalletModel::getTransactionTableModel() const
{
    return transactionTableModel;
}

RecentRequestsTableModel* WalletModel::getRecentRequestsTableModel() const
{
    return recentRequestsTableModel;
}

WalletModel::EncryptionStatus WalletModel::getEncryptionStatus() const
{
    if(!m_wallet->isCrypted())
    {
        // A previous bug allowed for watchonly wallets to be encrypted (encryption keys set, but nothing is actually encrypted).
        // To avoid misrepresenting the encryption status of such wallets, we only return NoKeys for watchonly wallets that are unencrypted.
        if (m_wallet->privateKeysDisabled()) {
            return NoKeys;
        }
        return Unencrypted;
    }
    else if(m_wallet->isLocked())
    {
        return Locked;
    }
    else
    {
        return Unlocked;
    }
}

bool WalletModel::setWalletEncrypted(const SecureString& passphrase)
{
    return m_wallet->encryptWallet(passphrase);
}

bool WalletModel::setWalletLocked(bool locked, const SecureString &passPhrase)
{
    if(locked)
    {
        // Lock
        return m_wallet->lock();
    }
    else
    {
        // Unlock
        return m_wallet->unlock(passPhrase);
    }
}

bool WalletModel::changePassphrase(const SecureString &oldPass, const SecureString &newPass)
{
    m_wallet->lock(); // Make sure wallet is locked before attempting pass change
    return m_wallet->changeWalletPassphrase(oldPass, newPass);
}

bool WalletModel::autoBackupWallet(QString& strBackupWarningRet, QString& strBackupErrorRet)
{
    bilingual_str strBackupError;
    std::vector<bilingual_str> warnings;
    bool result = m_wallet->autoBackupWallet("", strBackupError, warnings);
    strBackupWarningRet = QString::fromStdString(Join(warnings, Untranslated("\n")).translated);
    strBackupErrorRet = QString::fromStdString(strBackupError.translated);
    return result;
}

int64_t WalletModel::getKeysLeftSinceAutoBackup() const
{
    return m_wallet->getKeysLeftSinceAutoBackup();
}

// Handlers for core signals
static void NotifyUnload(WalletModel* walletModel)
{
    qDebug() << "NotifyUnload";
    bool invoked = QMetaObject::invokeMethod(walletModel, "unload", Qt::QueuedConnection);
    assert(invoked);
}

static void NotifyKeyStoreStatusChanged(WalletModel *walletmodel)
{
    qDebug() << "NotifyKeyStoreStatusChanged";
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateStatus", Qt::QueuedConnection);
    assert(invoked);
}

static void NotifyAddressBookChanged(WalletModel *walletmodel,
        const CTxDestination &address, const std::string &label, bool isMine,
        const std::string &purpose, ChangeType status)
{
    QString strAddress = QString::fromStdString(EncodeDestination(address));
    QString strLabel = QString::fromStdString(label);
    QString strPurpose = QString::fromStdString(purpose);

    qDebug() << "NotifyAddressBookChanged: " + strAddress + " " + strLabel + " isMine=" + QString::number(isMine) + " purpose=" + strPurpose + " status=" + QString::number(status);
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateAddressBook",
                              Q_ARG(QString, strAddress),
                              Q_ARG(QString, strLabel),
                              Q_ARG(bool, isMine),
                              Q_ARG(QString, strPurpose),
                              Q_ARG(int, status));
    assert(invoked);
}

static void NotifyTransactionChanged(WalletModel *walletmodel, const uint256 &hash, ChangeType status)
{
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateTransaction", Qt::QueuedConnection);
    assert(invoked);

    // For new transactions, check if dust protection should lock UTXOs
    if (status == CT_NEW) {
        QString hashStr = QString::fromStdString(hash.ToString());
        invoked = QMetaObject::invokeMethod(walletmodel, "checkAndLockDustOutputs", Qt::QueuedConnection,
                                            Q_ARG(QString, hashStr));
        assert(invoked);
    }
}

static void NotifyISLockReceived(WalletModel *walletmodel)
{
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateNumISLocks", Qt::QueuedConnection);
    assert(invoked);
}

static void NotifyChainLockReceived(WalletModel *walletmodel, int chainLockHeight)
{
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateChainLockHeight", Qt::QueuedConnection,
                              Q_ARG(int, chainLockHeight));
    assert(invoked);
}

static void ShowProgress(WalletModel *walletmodel, const std::string &title, int nProgress)
{
    // emits signal "showProgress"
    bool invoked = QMetaObject::invokeMethod(walletmodel, "showProgress", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(title)),
                              Q_ARG(int, nProgress));
    assert(invoked);
}

static void NotifyWatchonlyChanged(WalletModel *walletmodel, bool fHaveWatchonly)
{
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateWatchOnlyFlag", Qt::QueuedConnection,
                              Q_ARG(bool, fHaveWatchonly));
    assert(invoked);
}

static void NotifyCanGetAddressesChanged(WalletModel* walletmodel)
{
    bool invoked = QMetaObject::invokeMethod(walletmodel, "canGetAddressesChanged");
    assert(invoked);
}

void WalletModel::subscribeToCoreSignals()
{
    // Connect signals to wallet
    m_handler_unload = m_wallet->handleUnload(std::bind(&NotifyUnload, this));
    m_handler_status_changed = m_wallet->handleStatusChanged(std::bind(&NotifyKeyStoreStatusChanged, this));
    m_handler_address_book_changed = m_wallet->handleAddressBookChanged(std::bind(NotifyAddressBookChanged, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));
    m_handler_transaction_changed = m_wallet->handleTransactionChanged(std::bind(NotifyTransactionChanged, this, std::placeholders::_1, std::placeholders::_2));
    m_handler_islock_received = m_wallet->handleInstantLockReceived(std::bind(NotifyISLockReceived, this));
    m_handler_chainlock_received = m_wallet->handleChainLockReceived(std::bind(NotifyChainLockReceived, this, std::placeholders::_1));
    m_handler_show_progress = m_wallet->handleShowProgress(std::bind(ShowProgress, this, std::placeholders::_1, std::placeholders::_2));
    m_handler_watch_only_changed = m_wallet->handleWatchOnlyChanged(std::bind(NotifyWatchonlyChanged, this, std::placeholders::_1));
    m_handler_can_get_addrs_changed = m_wallet->handleCanGetAddressesChanged(std::bind(NotifyCanGetAddressesChanged, this));
}

void WalletModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    m_handler_unload->disconnect();
    m_handler_status_changed->disconnect();
    m_handler_address_book_changed->disconnect();
    m_handler_transaction_changed->disconnect();
    m_handler_islock_received->disconnect();
    m_handler_chainlock_received->disconnect();
    m_handler_show_progress->disconnect();
    m_handler_watch_only_changed->disconnect();
    m_handler_can_get_addrs_changed->disconnect();
}

// WalletModel::UnlockContext implementation
WalletModel::UnlockContext WalletModel::requestUnlock()
{
    // Bugs in earlier versions may have resulted in wallets with private keys disabled to become "encrypted"
    // (encryption keys are present, but not actually doing anything).
    // To avoid issues with such wallets, check if the wallet has private keys disabled, and if so, return a context
    // that indicates the wallet is not encrypted.
    if (m_wallet->privateKeysDisabled()) {
        return UnlockContext(this, /*valid=*/true, /*was_locked=*/false);
    }

    EncryptionStatus encStatusOld = getEncryptionStatus();

    // Wallet was completely locked
    bool was_locked = (encStatusOld == Locked);

    if (was_locked) {
        // Request UI to unlock wallet
        Q_EMIT requireUnlock();
    }

    EncryptionStatus encStatusNew = getEncryptionStatus();

    // If wallet is still locked, unlock failed or was cancelled, mark context as invalid
    bool fInvalid = (encStatusNew == Locked);
    // Wallet was not locked, keep it unlocked
    bool fKeepUnlocked = !was_locked;

    return UnlockContext(this, !fInvalid, !fKeepUnlocked);
}

WalletModel::UnlockContext::UnlockContext(WalletModel *_wallet, bool _valid, bool _was_locked):
        wallet(_wallet),
        valid(_valid),
        was_locked(_was_locked)
{
}

WalletModel::UnlockContext::~UnlockContext()
{
    if(valid && was_locked)
    {
        wallet->setWalletLocked(true);
    }
}

bool WalletModel::displayAddress(std::string sAddress)
{
    CTxDestination dest = DecodeDestination(sAddress);
    bool res = false;
    try {
        res = m_wallet->displayAddress(dest);
    } catch (const std::runtime_error& e) {
        QMessageBox::critical(nullptr, tr("Can't display address"), e.what());
    }
    return res;
}

bool WalletModel::isWalletEnabled()
{
   return !gArgs.GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET);
}

QString WalletModel::getWalletName() const
{
    return QString::fromStdString(m_wallet->getWalletName());
}

QString WalletModel::getDisplayName() const
{
    const QString name = getWalletName();
    return name.isEmpty() ? "["+tr("default wallet")+"]" : name;
}

bool WalletModel::isMultiwallet() const
{
    return m_node.walletLoader().getWallets().size() > 1;
}

uint256 WalletModel::getLastBlockProcessed() const
{
    return m_client_model ? m_client_model->getBestBlockHash() : uint256{};
}
