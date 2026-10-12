// Copyright (c) 2011-2021 The Bitcoin Core developers
// Copyright (c) 2014-2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/sendcoinsdialog.h>
#include <qt/forms/ui_sendcoinsdialog.h>

#include <qt/addresstablemodel.h>
#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/coincontroldialog.h>
#include <qt/guiutil.h>
#include <qt/guiutil_font.h>
#include <qt/optionsmodel.h>
#include <qt/sendcoinsentry.h>

#include <qt/shieldedsendworker.h>

#include <chainparams.h>
#include <interfaces/node.h>
#include <QPointer>
#include <key_io.h>
#include <node/interface_ui.h>
#include <policy/fees.h>
#include <sapling/sapling_address.h>
#include <sapling/sapling_tx_payload.h>
#include <txmempool.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/wallet.h>
#include <chrono>

using wallet::CCoinControl;
using wallet::DEFAULT_PAY_TX_FEE;

#include <array>
#include <QThread>
#include <fstream>
#include <memory>

#include <QScrollBar>
#include <QSettings>
#include <QThread>

static constexpr std::array confTargets{2, 4, 6, 12, 24, 48, 144, 504, 1008};
int getConfTargetForIndex(int index) {
    if (index+1 > static_cast<int>(confTargets.size())) {
        return confTargets.back();
    }
    if (index < 0) {
        return confTargets[0];
    }
    return confTargets[index];
}
int getIndexForConfTarget(int target) {
    for (unsigned int i = 0; i < confTargets.size(); i++) {
        if (confTargets[i] >= target) {
            return i;
        }
    }
    return confTargets.size() - 1;
}

SendCoinsDialog::SendCoinsDialog(QWidget* parent) :
    QDialog(parent, GUIUtil::dialog_flags),
    ui(new Ui::SendCoinsDialog),
    m_coin_control(new CCoinControl)
{
    ui->setupUi(this);

    GUIUtil::setFont({ui->labelCoinControlFeatures,
                      ui->labelCoinControlInsuffFunds,
                      ui->labelCoinControlQuantityText,
                      ui->labelCoinControlBytesText,
                      ui->labelCoinControlAmountText,
                      ui->labelCoinControlFeeText,
                      ui->labelCoinControlAfterFeeText,
                      ui->labelCoinControlChangeText,
                      ui->labelFeeHeadline,
                      ui->fallbackFeeWarningLabel,
                      ui->labelPayFrom
                     }, {GUIUtil::FontWeight::Bold});

    GUIUtil::setFont({ui->labelBalance,
                      ui->labelBalanceName,
                     }, {GUIUtil::FontWeight::Bold, 14});

    GUIUtil::setFont({ui->labelCoinControlFeatures
                     }, {GUIUtil::FontWeight::Bold, 16});

    ui->checkBoxCoinControlChange->setEnabled(true);
    m_change_address_tooltip = ui->checkBoxCoinControlChange->toolTip();
    GUIUtil::setupAddressWidget(ui->lineEditCoinControlChange, this);

    addEntry();

    GUIUtil::updateFonts();

    connect(ui->addButton, &QPushButton::clicked, this, &SendCoinsDialog::addEntry);
    connect(ui->clearButton, &QPushButton::clicked, this, &SendCoinsDialog::clear);

    // Coin Control
    connect(ui->pushButtonCoinControl, &QPushButton::clicked, this, &SendCoinsDialog::coinControlButtonClicked);
    connect(ui->checkBoxCoinControlChange, &QCheckBox::stateChanged, this, &SendCoinsDialog::coinControlChangeChecked);
    connect(ui->lineEditCoinControlChange, &QValidatedLineEdit::textEdited, this, &SendCoinsDialog::coinControlChangeEdited);

    // Coin Control: clipboard actions
    QAction *clipboardQuantityAction = new QAction(tr("Copy quantity"), this);
    QAction *clipboardAmountAction = new QAction(tr("Copy amount"), this);
    QAction *clipboardFeeAction = new QAction(tr("Copy fee"), this);
    QAction *clipboardAfterFeeAction = new QAction(tr("Copy after fee"), this);
    QAction *clipboardBytesAction = new QAction(tr("Copy bytes"), this);
    QAction *clipboardChangeAction = new QAction(tr("Copy change"), this);
    connect(clipboardQuantityAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardQuantity);
    connect(clipboardAmountAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardAmount);
    connect(clipboardFeeAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardFee);
    connect(clipboardAfterFeeAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardAfterFee);
    connect(clipboardBytesAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardBytes);
    connect(clipboardChangeAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardChange);
    ui->labelCoinControlQuantity->addAction(clipboardQuantityAction);
    ui->labelCoinControlAmount->addAction(clipboardAmountAction);
    ui->labelCoinControlFee->addAction(clipboardFeeAction);
    ui->labelCoinControlAfterFee->addAction(clipboardAfterFeeAction);
    ui->labelCoinControlBytes->addAction(clipboardBytesAction);
    ui->labelCoinControlChange->addAction(clipboardChangeAction);

    // init transaction fee section
    QSettings settings;
    if (!settings.contains("fFeeSectionMinimized"))
        settings.setValue("fFeeSectionMinimized", true);
    if (!settings.contains("nFeeRadio") && settings.contains("nTransactionFee") && settings.value("nTransactionFee").toLongLong() > 0) // compatibility
        settings.setValue("nFeeRadio", 1); // custom
    if (!settings.contains("nFeeRadio"))
        settings.setValue("nFeeRadio", 0); // recommended
    if (!settings.contains("nSmartFeeSliderPosition"))
        settings.setValue("nSmartFeeSliderPosition", 0);
    if (!settings.contains("nTransactionFee"))
        settings.setValue("nTransactionFee", (qint64)DEFAULT_PAY_TX_FEE);
    ui->groupFee->setId(ui->radioSmartFee, 0);
    ui->groupFee->setId(ui->radioCustomFee, 1);
    ui->groupFee->button((int)std::max(0, std::min(1, settings.value("nFeeRadio").toInt())))->setChecked(true);
    ui->customFee->SetAllowEmpty(false);
    ui->customFee->setValue(settings.value("nTransactionFee").toLongLong());
    minimizeFeeSection(settings.value("fFeeSectionMinimized").toBool());

    ui->sendButton->setText(tr("S&end"));
    ui->sendButton->setToolTip(tr("Confirm the send action"));

    GUIUtil::ExceptionSafeConnect(ui->sendButton, &QPushButton::clicked, this, &SendCoinsDialog::sendButtonClicked);

    // Pay from: transparent coins or shielded notes
    connect(ui->radioPayFromTransparent, &QRadioButton::toggled, this, &SendCoinsDialog::payFromChanged);
    m_shielded_fee_timer.setSingleShot(true);
    m_shielded_fee_timer.setInterval(300);
    connect(&m_shielded_fee_timer, &QTimer::timeout, this, &SendCoinsDialog::updateFeeMinimizedLabel);
}

void SendCoinsDialog::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    if (_clientModel) {
        connect(_clientModel, &ClientModel::numBlocksChanged, this, &SendCoinsDialog::updateNumberOfBlocks);
    }
}

void SendCoinsDialog::setModel(WalletModel *_model)
{
    this->model = _model;

    if(_model && _model->getOptionsModel())
    {
        for(int i = 0; i < ui->entries->count(); ++i)
        {
            SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
            if(entry)
            {
                entry->setModel(_model);
            }
        }

        interfaces::WalletBalances balances = _model->wallet().getBalances();
        setBalance(balances);
        connect(_model, &WalletModel::balanceChanged, this, &SendCoinsDialog::setBalance);
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &SendCoinsDialog::updateDisplayUnit);
        updateDisplayUnit();

        // Coin Control
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
        connect(_model->getOptionsModel(), &OptionsModel::coinControlFeaturesChanged, this, &SendCoinsDialog::coinControlFeatureChanged);
        ui->frameCoinControl->setVisible(_model->getOptionsModel()->getCoinControlFeatures());
        coinControlUpdateLabels();

        connect(_model->getOptionsModel(), &OptionsModel::keepChangeAddressChanged, this, &SendCoinsDialog::keepChangeAddressChanged);
        fKeepChangeAddress = _model->getOptionsModel()->getKeepChangeAddress();

        QSettings settings;
        if (fKeepChangeAddress && settings.contains("sCustomChangeAddress")) {
            ui->checkBoxCoinControlChange->setChecked(true);
            ui->lineEditCoinControlChange->setText(settings.value("sCustomChangeAddress").toString());
            coinControlChangeEdited(ui->lineEditCoinControlChange->text());
        }

        // fee section
        for (const int n : confTargets) {
            ui->confTargetSelector->addItem(tr("%1 (%2 blocks)").arg(GUIUtil::formatNiceTimeOffset(n*Params().GetConsensus().nPowTargetSpacing)).arg(n));
        }
        connect(ui->confTargetSelector, qOverload<int>(&QComboBox::currentIndexChanged), this, &SendCoinsDialog::updateSmartFeeLabel);
        connect(ui->confTargetSelector, qOverload<int>(&QComboBox::currentIndexChanged), this, &SendCoinsDialog::coinControlUpdateLabels);

#if (QT_VERSION >= QT_VERSION_CHECK(5, 15, 0))
        connect(ui->groupFee, &QButtonGroup::idClicked, this, &SendCoinsDialog::updateFeeSectionControls);
        connect(ui->groupFee, &QButtonGroup::idClicked, this, &SendCoinsDialog::coinControlUpdateLabels);
#else
        connect(ui->groupFee, qOverload<int>(&QButtonGroup::buttonClicked), this, &SendCoinsDialog::updateFeeSectionControls);
        connect(ui->groupFee, qOverload<int>(&QButtonGroup::buttonClicked), this, &SendCoinsDialog::coinControlUpdateLabels);
#endif

        connect(ui->customFee, &BitcoinAmountField::valueChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
        CAmount requiredFee = model->wallet().getRequiredFee(1000);
        ui->customFee->SetMinValue(requiredFee);
        if (ui->customFee->value() < requiredFee) {
            ui->customFee->setValue(requiredFee);
        }
        updateFeeSectionControls();
        updateSmartFeeLabel();

        if (model->wallet().hasExternalSigner()) {
            //: "device" usually means a hardware wallet.
            ui->sendButton->setText(tr("Sign on device"));
            if (gArgs.GetArg("-signer", "") != "") {
                ui->sendButton->setEnabled(true);
                ui->sendButton->setToolTip(tr("Connect your hardware wallet first."));
            } else {
                ui->sendButton->setEnabled(false);
                //: "External signer" means using devices such as hardware wallets.
                ui->sendButton->setToolTip(tr("Set external signer script path in Options -> Wallet"));
            }
        } else if (model->wallet().privateKeysDisabled()) {
            ui->sendButton->setText(tr("Cr&eate Unsigned"));
            ui->sendButton->setToolTip(tr("Creates a Partially Signed Blockchain Transaction (PSBT) for use with e.g. an offline %1 wallet, or a PSBT-compatible hardware wallet.").arg(PACKAGE_NAME));
        }

        // set the smartfee-sliders default value (wallets default conf.target or last stored value)
        if (settings.value("nSmartFeeSliderPosition").toInt() != 0) {
            // migrate nSmartFeeSliderPosition to nConfTarget
            // nConfTarget is available since 0.15 (replaced nSmartFeeSliderPosition)
            int nConfirmTarget = 25 - settings.value("nSmartFeeSliderPosition").toInt(); // 25 == old slider range
            settings.setValue("nConfTarget", nConfirmTarget);
            settings.remove("nSmartFeeSliderPosition");
        }
        if (settings.value("nConfTarget").toInt() == 0)
            ui->confTargetSelector->setCurrentIndex(getIndexForConfTarget(model->wallet().getConfirmTarget()));
        else
            ui->confTargetSelector->setCurrentIndex(getIndexForConfTarget(settings.value("nConfTarget").toInt()));

        // Pay from: shielded notes need the wallet's own spending keys
        const bool can_spend_shielded = !model->wallet().privateKeysDisabled() && !model->wallet().hasExternalSigner();
        ui->radioPayFromShielded->setEnabled(can_spend_shielded);
        if (can_spend_shielded && settings.value("fPayFromShielded", false).toBool()) {
            ui->radioPayFromShielded->setChecked(true);
        }
        payFromChanged();
    }
}

SendCoinsDialog::~SendCoinsDialog()
{
    // If a shielded send thread is still running (Groth16 proof generation),
    // ask it to quit and wait for it to finish before destroying the dialog.
    // Without this, the thread's signal connections back to `this` would
    // fire into a destroyed object.
    if (m_shieldedThread && m_shieldedThread->isRunning()) {
        m_shieldedThread->quit();
        m_shieldedThread->wait();
    }

    QSettings settings;
    if (fKeepChangeAddress) {
        settings.setValue("sCustomChangeAddress", ui->lineEditCoinControlChange->text());
    }
    settings.setValue("fFeeSectionMinimized", fFeeMinimized);
    settings.setValue("nFeeRadio", ui->groupFee->checkedId());
    settings.setValue("nConfTarget", getConfTargetForIndex(ui->confTargetSelector->currentIndex()));
    settings.setValue("nTransactionFee", (qint64)ui->customFee->value());
    settings.setValue("fPayFromShielded", payFromShielded());

    delete ui;
}

bool SendCoinsDialog::PrepareSendText(QString& question_string, QString& informative_text, QString& detailed_text)
{
    QList<SendCoinsRecipient> recipients;
    bool valid = true;

    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            if(entry->validate(model->node()))
            {
                recipients.append(entry->getValue());
            }
            else if (valid)
            {
                ui->scrollArea->ensureWidgetVisible(entry);
                valid = false;
            }
        }
    }

    if(!valid || recipients.isEmpty())
    {
        return false;
    }

    fNewRecipientAllowed = false;
    // request unlock only if locked
    WalletModel::EncryptionStatus encStatus = model->getEncryptionStatus();
    if(encStatus == model->Locked)
    {
        WalletModel::UnlockContext ctx(model->requestUnlock());
        if(!ctx.isValid())
        {
            // Unlock wallet was cancelled
            fNewRecipientAllowed = true;
            return false;
        }
        return send(recipients, question_string, informative_text, detailed_text);
    } // WalletModel::UnlockContext

    // already unlocked or not encrypted at all
    return send(recipients, question_string, informative_text, detailed_text);
}

bool SendCoinsDialog::send(const QList<SendCoinsRecipient>& recipients, QString& question_string, QString& informative_text, QString& detailed_text)
{
    // prepare transaction for getting txFee earlier
    m_current_transaction = std::make_unique<WalletModelTransaction>(recipients);
    WalletModel::SendCoinsReturn prepareStatus;

    updateCoinControlState();

    prepareStatus = model->prepareTransaction(*m_current_transaction, *m_coin_control);

    // process prepareStatus and on error generate message shown to user
    processSendCoinsReturn(prepareStatus,
        BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), m_current_transaction->getTransactionFee()));

    // Handle DuplicateAddress as a warning that requires user confirmation
    if (prepareStatus.status == WalletModel::DuplicateAddress) {
        QMessageBox::StandardButton reply = QMessageBox::question(
            this,
            tr("Confirm duplicate recipients"),
            tr("You are sending to the same address multiple times in a single transaction. "
               "This is unusual and may not be what you intended. "
               "Are you sure you want to proceed?"),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel
        );

        if (reply != QMessageBox::Yes) {
            fNewRecipientAllowed = true;
            return false;
        }
        // User confirmed, continue
    } else if (prepareStatus.status != WalletModel::OK) {
        fNewRecipientAllowed = true;
        return false;
    }

    QStringList formatted;
    for (const SendCoinsRecipient &rcp : m_current_transaction->getRecipients())
    {
        // generate amount string with wallet name in case of multiwallet
        QString amount = BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), rcp.amount);
        if (model->isMultiwallet()) {
            amount = tr("%1 from wallet '%2'").arg(amount, model->getWalletName());
        }

        // generate address string
        QString address = rcp.address;

        QString recipientElement;

        {
            if(rcp.label.length() > 0) // label with address
            {
                recipientElement.append(tr("%1 to '%2'").arg(amount, rcp.label));
                recipientElement.append(QString(" (%1)").arg(address));
            }
            else // just address
            {
                recipientElement.append(tr("%1 to %2").arg(amount, address));
            }
        }
        formatted.append(recipientElement);
    }

    // Limit number of displayed entries
    QStringList formatted_short(formatted);
    if (formatted_short.size() > MAX_SEND_POPUP_ENTRIES) {
        formatted_short.erase(formatted_short.begin() + MAX_SEND_POPUP_ENTRIES, formatted_short.end());
    }

    // Wrap the whole text in a global span to control its styling properly
    question_string.append("<span style='font-weight:normal;'>");

    /*: Message displayed when attempting to create a transaction. Cautionary text to prompt the user to verify
        that the displayed transaction details represent the transaction the user intends to create. */
    question_string.append(tr("Do you want to create this transaction?"));
    question_string.append("<br /><span style='font-size:10pt;'>");
    if (model->wallet().privateKeysDisabled() && !model->wallet().hasExternalSigner()) {
        question_string.append(tr("Do you want to draft this transaction?"));
        /*: Text to inform a user attempting to create a transaction of their current options. At this stage,
            a user can only create a PSBT. This string is displayed when private keys are disabled and an external
            signer is not available. */
        question_string.append(tr("Please, review your transaction proposal. This will produce a Partially Signed Blockchain Transaction (PSBT) which you can save or copy and then sign with e.g. an offline %1 wallet, or a PSBT-compatible hardware wallet.").arg(PACKAGE_NAME));
    } else if (model->getOptionsModel()->getEnablePSBTControls()) {
        /*: Text to inform a user attempting to create a transaction of their current options. At this stage,
            a user can send their transaction or create a PSBT. This string is displayed when both private keys
            and PSBT controls are enabled. */
        question_string.append(tr("Please, review your transaction. You can create and send this transaction or create a Partially Signed Blockchain Transaction (PSBT), which you can save or copy and then sign with, e.g., an offline %1 wallet, or a PSBT-compatible hardware wallet.").arg(PACKAGE_NAME));
    } else {
        /*: Text to prompt a user to review the details of the transaction they are attempting to send. */
        question_string.append(tr("Please, review your transaction."));
    }
    question_string.append("</span>");
    question_string.append("<br /><br />");
    question_string.append(formatted_short.join("<br />"));
    question_string.append("<br />");

    question_string.append(tr("using") + " <b>" + tr("any available funds") + "</b>");

    int messageEntries = formatted.size();
    int displayedEntries = formatted_short.size();

    if (displayedEntries < messageEntries) {
        question_string.append("<br />");
        question_string.append("<span style='" + GUIUtil::getThemedStyleQString(GUIUtil::ThemedStyle::TS_WARNING) + "'>");
        question_string.append(tr("<b>(%1 of %2 entries displayed)</b>").arg(displayedEntries).arg(messageEntries));
        question_string.append("</span>");
    }

    CAmount txFee = m_current_transaction->getTransactionFee();

    if(txFee > 0)
    {
        // append fee string if a fee is required
        question_string.append("<hr /><b>");
        question_string.append(QString("<b>%1</b>: <span style='%2'>%3</span>").arg(tr("Transaction fee"))
            .arg(GUIUtil::getThemedStyleQString(GUIUtil::ThemedStyle::TS_ERROR))
            .arg(BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), txFee)));

    }

    // Show some additioinal information
    question_string.append("<hr />");
    // append transaction size
    unsigned int txSize = m_current_transaction->getTransactionSize();
    question_string.append(tr("Transaction size: %1").arg(QString::number((double)txSize / 1000)) + " kB");
    question_string.append("<br />");
    CFeeRate feeRate(txFee, txSize > 0 ? txSize : 1); // guard against div-by-zero
    question_string.append(tr("Fee rate: %1").arg(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), feeRate.GetFeePerK())) + "/kB");

    // add total amount in all subdivision units
    question_string.append("<hr />");
    CAmount totalAmount = m_current_transaction->getTotalTransactionAmount() + txFee;
    QStringList alternativeUnits;
    for (const BitcoinUnit u : BitcoinUnits::availableUnits()) {
        if(u != model->getOptionsModel()->getDisplayUnit())
            alternativeUnits.append(BitcoinUnits::formatHtmlWithUnit(u, totalAmount));
    }

    // Show total amount + all alternative units
    question_string.append(QString("<b>%1</b>: <b>%2</b>").arg(tr("Total Amount"))
        .arg(BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), totalAmount)));
    question_string.append(QString("<br /><span style='font-size:10pt; font-weight:normal;'>(=%1)</span>")
        .arg(alternativeUnits.join(" " + tr("or") + " ")));

    // Close the global span we opened at the very beginning
    question_string.append("</span>");

    if (formatted.size() > 1) {
        informative_text = tr("To review recipient list click \"Show Details…\"");
        detailed_text = formatted.join("\n\n");
    }

    return true;
}

bool SendCoinsDialog::payFromShielded() const
{
    return ui->radioPayFromShielded->isChecked();
}

bool SendCoinsDialog::isShieldedSend() const
{
    if (payFromShielded()) return true;
    for (int i = 0; i < ui->entries->count(); ++i) {
        SendCoinsEntry* entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        sapling::SaplingPaymentAddress addr;
        if (entry && !entry->isHidden() && DecodeSaplingAddress(entry->getValue().address.toStdString(), addr)) {
            return true;
        }
    }
    return false;
}

CAmount SendCoinsDialog::shieldedAvailableBalance(bool selected_only) const
{
    CAmount total = 0;
    for (const auto& note : model->wallet().listSpendableSaplingNotes(/*minconf=*/1)) {
        if (selected_only && !m_selected_notes.count(note.cmu)) continue;
        total += note.value;
    }
    return total;
}

wallet::SaplingSendSource SendCoinsDialog::shieldedSendSource() const
{
    wallet::SaplingSendSource source;
    source.shielded = payFromShielded();
    if (source.shielded) {
        source.notes.assign(m_selected_notes.begin(), m_selected_notes.end());
    } else {
        m_coin_control->ListSelected(source.coins);
        source.change_dest = m_coin_control->destChange;
    }
    return source;
}

QString SendCoinsDialog::shieldedFeeText()
{
    static_assert(SAPLING_PER_SPEND_FEE == SAPLING_PER_OUTPUT_FEE, "the fee text uses one rate for inputs and outputs");
    const BitcoinUnit unit = model->getOptionsModel()->getDisplayUnit();

    // The fee for what is entered so far, if it can be sent
    QList<SendCoinsRecipient> recipients;
    for (int i = 0; i < ui->entries->count(); ++i) {
        SendCoinsEntry* entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if (!entry || entry->isHidden()) continue;
        const SendCoinsRecipient rcp = entry->getValue();
        sapling::SaplingPaymentAddress addr;
        const bool valid_address = DecodeSaplingAddress(rcp.address.toStdString(), addr) || IsValidDestinationString(rcp.address.toStdString());
        if (valid_address && rcp.amount > 0) recipients.append(rcp);
    }
    if (!recipients.isEmpty()) {
        try {
            const auto plan = model->planSaplingSend(shieldedSendSource(), recipients);
            return tr("%1 (fixed shielded fee)").arg(BitcoinUnits::formatWithUnit(unit, plan.fee));
        } catch (const std::exception&) {
            // Not sendable yet (e.g. insufficient funds): show how the fee is made up
        }
    }
    return tr("%1 + %2 per shielded input and output (fixed shielded fee)")
        .arg(BitcoinUnits::formatWithUnit(unit, SAPLING_BASE_FEE), BitcoinUnits::formatWithUnit(unit, SAPLING_PER_SPEND_FEE));
}

bool SendCoinsDialog::sendShielded(const QList<SendCoinsRecipient>& recipients, bool relockOnComplete)
{
    wallet::SaplingSendSource source = shieldedSendSource();

    wallet::SaplingSendPlan plan;
    try {
        plan = model->planSaplingSend(source, recipients);
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Shielded Send"), QString::fromStdString(e.what()));
        fNewRecipientAllowed = true;
        return false;
    }

    // Confirm with user
    const BitcoinUnit unit = model->getOptionsModel()->getDisplayUnit();
    auto fmt = [unit](CAmount amount) { return BitcoinUnits::formatWithUnit(unit, amount); };

    CAmount totalAmount = 0;
    for (const CAmount amount : plan.amounts) totalAmount += amount;

    QStringList lines;
    lines << tr("Send %1 via shielded transaction?").arg(fmt(totalAmount)) << QString();

    const int n_inputs = static_cast<int>(source.shielded ? plan.notes.size() : plan.coins.size());
    lines << (source.shielded ? tr("From: Shielded funds, %n note(s)", "", n_inputs)
                              : tr("From: Transparent funds, %n input(s)", "", n_inputs));
    constexpr size_t MAX_LISTED_SOURCES = 10;
    for (size_t i = 0; i < plan.sources.size() && i < MAX_LISTED_SOURCES; ++i) {
        const auto& group = plan.sources[i];
        QString line = tr("%1 from %2").arg(fmt(group.value), QString::fromStdString(group.address));
        if (group.is_change) line += " " + tr("(change)");
        lines << "    " + line;
    }
    if (plan.sources.size() > MAX_LISTED_SOURCES) {
        lines << "    " + tr("…and %n more address(es)", "", static_cast<int>(plan.sources.size() - MAX_LISTED_SOURCES));
    }

    lines << QString() << tr("To:");
    for (int i = 0; i < recipients.size(); ++i) {
        const auto& rcp = recipients[i];
        lines << "    " + tr("%1 to %2").arg(fmt(plan.amounts[i]), rcp.address);
        if (!rcp.memo.isEmpty()) {
            lines << "    " + tr("Memo: %1").arg(rcp.memo);
        }
    }

    lines << QString() << tr("Fee: %1").arg(fmt(plan.fee));
    if (plan.change > 0) {
        if (source.shielded) {
            lines << tr("Change: %1, back to your shielded funds").arg(fmt(plan.change));
        } else if (IsValidDestination(source.change_dest)) {
            lines << tr("Change: %1, to %2").arg(fmt(plan.change), QString::fromStdString(EncodeDestination(source.change_dest)));
        } else {
            lines << tr("Change: %1, to a new change address").arg(fmt(plan.change));
        }
    }
    lines << QString() << tr("Proof generation may take a moment.");

    // Same confirmation as transparent sends (Yes is enabled after a short
    // delay), as plain text: the memo is user input and must not be rendered
    // as rich text
    auto confirmationDialog = new SendConfirmationDialog(tr("Confirm Shielded Send"), lines.join("\n"), /*informative_text=*/"", /*detailed_text=*/"",
                                                         SEND_CONFIRM_DELAY, /*enable_send=*/true, /*always_show_unsigned=*/false, this);
    confirmationDialog->setAttribute(Qt::WA_DeleteOnClose);
    confirmationDialog->setTextFormat(Qt::PlainText);
    if (confirmationDialog->exec() != QMessageBox::Yes) {
        fNewRecipientAllowed = true;
        return false;
    }

    // Send exactly the inputs that were confirmed
    source.coins = plan.coins;
    source.notes = plan.notes;

    // Show progress dialog
    auto* progress = new QProgressDialog(
        tr("Generating shielded transaction proof..."), QString(), 0, 0, this);
    progress->setWindowModality(Qt::WindowModal);
    progress->setMinimumDuration(0);
    progress->setCancelButton(nullptr);
    progress->show();

    auto* thread = new QThread;
    auto* worker = new ShieldedSendWorker(model, source, recipients);
    worker->moveToThread(thread);

    // Track the thread so the destructor can wait for it if the dialog
    // is closed while Groth16 proof generation is still running.
    m_shieldedThread = thread;

    // Use QPointer to guard against use-after-free if wallet model is destroyed
    // while Groth16 proof generation runs on the background thread.
    QPointer<WalletModel> safeModel(model);

    connect(thread, &QThread::started, worker, &ShieldedSendWorker::process);
    connect(worker, &ShieldedSendWorker::finished, this, [this, relockOnComplete, safeModel, progress, thread, worker](const QString& txid) {
        progress->close();
        progress->deleteLater();
        if (relockOnComplete && safeModel) {
            safeModel->setWalletLocked(true);
        }
        QMessageBox::information(this, tr("Shielded Send"),
            tr("Transaction sent successfully.\n\nTXID: %1").arg(txid));
        Q_EMIT coinsSent(uint256S(txid.toStdString()));
        accept();
        fNewRecipientAllowed = true;
        thread->quit();
        thread->wait();
        m_shieldedThread = nullptr;
    });
    connect(worker, &ShieldedSendWorker::error, this, [this, relockOnComplete, safeModel, progress, thread, worker](const QString& message) {
        progress->close();
        progress->deleteLater();
        if (relockOnComplete && safeModel) {
            safeModel->setWalletLocked(true);
        }
        QMessageBox::critical(this, tr("Shielded Send Failed"), message);
        fNewRecipientAllowed = true;
        thread->quit();
        thread->wait();
        m_shieldedThread = nullptr;
    });
    connect(thread, &QThread::finished, worker, &QObject::deleteLater);
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);

    thread->start();
    return true;
}

void SendCoinsDialog::sendButtonClicked([[maybe_unused]] bool checked)
{
    if(!model || !model->getOptionsModel())
        return;

    // Collect recipients and check for shielded addresses
    QList<SendCoinsRecipient> allRecipients;
    bool valid = true;
    for (int i = 0; i < ui->entries->count(); ++i) {
        SendCoinsEntry* entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if (entry) {
            if (entry->validate(model->node())) {
                allRecipients.append(entry->getValue());
            } else {
                valid = false;
            }
        }
    }

    if (!valid || allRecipients.isEmpty())
        return;

    // Shielded funds or a shielded recipient need a Sapling transaction
    if (isShieldedSend()) {
        fNewRecipientAllowed = false;
        WalletModel::EncryptionStatus encStatus = model->getEncryptionStatus();
        if (encStatus == model->Locked) {
            // Don't use UnlockContext RAII; its destructor would re-lock the
            // wallet before the background ShieldedSendWorker completes.
            // Instead, trigger the unlock dialog manually and let the worker's
            // finished/error signals re-lock when done.
            Q_EMIT model->requireUnlock();
            if (model->getEncryptionStatus() == model->Locked) {
                // Unlock was cancelled or failed
                fNewRecipientAllowed = true;
                return;
            }
            try {
                if (!sendShielded(allRecipients, /*relockOnComplete=*/true)) {
                    model->setWalletLocked(true); // Nothing was sent
                }
            } catch (...) {
                model->setWalletLocked(true); // Re-lock on exception
                fNewRecipientAllowed = true;
                throw;
            }
            return;
        }
        sendShielded(allRecipients);
        return;
    }

    // Standard transparent send path
    QString question_string, informative_text, detailed_text;
    if (!PrepareSendText(question_string, informative_text, detailed_text)) return;
    assert(m_current_transaction);

    const QString confirmation = tr("Confirm send coins");
    auto confirmationDialog = new SendConfirmationDialog(confirmation, question_string, informative_text, detailed_text, SEND_CONFIRM_DELAY, !model->wallet().privateKeysDisabled(), model->getOptionsModel()->getEnablePSBTControls(), this);
    confirmationDialog->setAttribute(Qt::WA_DeleteOnClose);
    // TODO: Replace QDialog::exec() with safer QDialog::show().
    const auto retval = static_cast<QMessageBox::StandardButton>(confirmationDialog->exec());

    if(retval != QMessageBox::Yes && retval != QMessageBox::Save)
    {
        fNewRecipientAllowed = true;
        return;
    }

    bool send_failure = false;
    if (retval == QMessageBox::Save) {
        CMutableTransaction mtx = CMutableTransaction{*(m_current_transaction->getWtx())};
        PartiallySignedTransaction psbtx(mtx);
        bool complete = false;
        // Always fill without signing first. This prevents an external signer
        // from being called prematurely and is not expensive.
        TransactionError err = model->wallet().fillPSBT(SIGHASH_ALL, false /* sign */, true /* bip32derivs */, nullptr, psbtx, complete);
        assert(!complete);
        assert(err == TransactionError::OK);
        if (model->wallet().hasExternalSigner()) {
            try {
                err = model->wallet().fillPSBT(SIGHASH_ALL, true /* sign */, true /* bip32derivs */, nullptr, psbtx, complete);
            } catch (const std::runtime_error& e) {
                QMessageBox::critical(nullptr, tr("Sign failed"), e.what());
                send_failure = true;
            }
            if (!send_failure && err == TransactionError::EXTERNAL_SIGNER_NOT_FOUND) {
                //: "External signer" means using devices such as hardware wallets.
                QMessageBox::critical(nullptr, tr("External signer not found"), "External signer not found");
                send_failure = true;
            }
            if (!send_failure && err == TransactionError::EXTERNAL_SIGNER_FAILED) {
                //: "External signer" means using devices such as hardware wallets.
                QMessageBox::critical(nullptr, tr("External signer failure"), "External signer failure");
                send_failure = true;
            }
            if (!send_failure && err != TransactionError::OK) {
                tfm::format(std::cerr, "Failed to sign PSBT");
                processSendCoinsReturn(WalletModel::TransactionCreationFailed);
                send_failure = true;
            }
            // fillPSBT does not always properly finalize
            if (!send_failure)
                complete = FinalizeAndExtractPSBT(psbtx, mtx);
        }

        // Broadcast transaction if complete (even with an external signer this
        // is not always the case, e.g. in a multisig wallet).
        if (!send_failure && complete) {
            const CTransactionRef tx = MakeTransactionRef(mtx);
            m_current_transaction->setWtx(tx);
            model->sendCoins(*m_current_transaction);
        }

        // Copy PSBT to clipboard and offer to save (fall through to cleanup)
        if (!send_failure && !complete) {
        // Serialize the PSBT
        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << psbtx;
        GUIUtil::setClipboard(EncodeBase64(ssTx.str()).c_str());
        QMessageBox msgBox;
        msgBox.setText("Unsigned Transaction");
        msgBox.setInformativeText("The PSBT has been copied to the clipboard. You can also save it.");
        msgBox.setStandardButtons(QMessageBox::Save | QMessageBox::Discard);
        msgBox.setDefaultButton(QMessageBox::Discard);
        switch (msgBox.exec()) {
        case QMessageBox::Save: {
            QString selectedFilter;
            QString fileNameSuggestion = "";
            bool first = true;
            for (const SendCoinsRecipient &rcp : m_current_transaction->getRecipients()) {
                if (!first) {
                    fileNameSuggestion.append(" - ");
                }
                QString labelOrAddress = rcp.label.isEmpty() ? rcp.address : rcp.label;
                QString amount = BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), rcp.amount);
                fileNameSuggestion.append(labelOrAddress + "-" + amount);
                first = false;
            }
            fileNameSuggestion.append(".psbt");
            QString filename = GUIUtil::getSaveFileName(this,
                tr("Save Transaction Data"), fileNameSuggestion,
                //: Expanded name of the binary PSBT file format. See: BIP 174.
                tr("Partially Signed Transaction (Binary)") + QLatin1String(" (*.psbt)"), &selectedFilter);
            if (filename.isEmpty()) {
                send_failure = true;
            } else {
                std::ofstream out{filename.toLocal8Bit().data(), std::ofstream::out | std::ofstream::binary};
                out << ssTx.str();
                out.close();
                Q_EMIT message(tr("PSBT saved"), "PSBT saved to disk", CClientUIInterface::MSG_INFORMATION);
            }
            break;
        }
        case QMessageBox::Discard:
            break;
        default:
            assert(false);
        } // msgBox.exec()
        } // end !send_failure && !complete
    } else {
        assert(!model->wallet().privateKeysDisabled());
        // now send the prepared transaction
        model->sendCoins(*m_current_transaction);
        Q_EMIT coinsSent(m_current_transaction->getWtx()->GetHash());
    }
    if (!send_failure) {
        accept();
        m_coin_control->UnSelectAll();
        coinControlUpdateLabels();
    }
    fNewRecipientAllowed = true;
    m_current_transaction.reset();
}

void SendCoinsDialog::clear()
{
    m_current_transaction.reset();

    // Clear coin control settings
    m_coin_control->UnSelectAll();
    m_selected_notes.clear();
    if (!fKeepChangeAddress) {
        ui->checkBoxCoinControlChange->setChecked(false);
        ui->lineEditCoinControlChange->clear();
    }
    coinControlUpdateLabels();

    // Remove entries until only one left
    while(ui->entries->count())
    {
        ui->entries->takeAt(0)->widget()->deleteLater();
    }
    addEntry();

    updateTabsAndLabels();
}

void SendCoinsDialog::reject()
{
    clear();
}

void SendCoinsDialog::accept()
{
    clear();
}

SendCoinsEntry *SendCoinsDialog::addEntry()
{
    SendCoinsEntry* entry = new SendCoinsEntry(this);
    entry->setModel(model);
    ui->entries->addWidget(entry);
    connect(entry, &SendCoinsEntry::removeEntry, this, &SendCoinsDialog::removeEntry);
    connect(entry, &SendCoinsEntry::useAvailableBalance, this, &SendCoinsDialog::useAvailableBalance);
    connect(entry, &SendCoinsEntry::payAmountChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
    connect(entry, &SendCoinsEntry::subtractFeeFromAmountChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
    connect(entry, &SendCoinsEntry::payToChanged, this, &SendCoinsDialog::updateShieldedState);

    // Focus the field, so that entry can start immediately
    entry->clear();
    entry->setFocus();
    ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());

    // Scroll to the newly added entry on a QueuedConnection because Qt doesn't
    // adjust the scroll area and scrollbar immediately when the widget is added.
    // Invoking on a DirectConnection will only scroll to the second-to-last entry.
    QMetaObject::invokeMethod(ui->scrollArea, [this] {
        if (ui->scrollArea->verticalScrollBar()) {
            ui->scrollArea->verticalScrollBar()->setValue(ui->scrollArea->verticalScrollBar()->maximum());
        }
    }, Qt::QueuedConnection);

    updateTabsAndLabels();
    return entry;
}

void SendCoinsDialog::updateTabsAndLabels()
{
    setupTabChain(nullptr);
    coinControlUpdateLabels();
}

void SendCoinsDialog::removeEntry(SendCoinsEntry* entry)
{
    entry->hide();

    // If the last entry is about to be removed add an empty one
    if (ui->entries->count() == 1)
        addEntry();

    entry->deleteLater();

    updateTabsAndLabels();
}

QWidget *SendCoinsDialog::setupTabChain(QWidget *prev)
{
    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            prev = entry->setupTabChain(prev);
        }
    }
    QWidget::setTabOrder(prev, ui->sendButton);
    QWidget::setTabOrder(ui->sendButton, ui->clearButton);
    QWidget::setTabOrder(ui->clearButton, ui->addButton);
    return ui->addButton;
}

void SendCoinsDialog::setAddress(const QString &address)
{
    SendCoinsEntry *entry = nullptr;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        SendCoinsEntry *first = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(0)->widget());
        if(first->isClear())
        {
            entry = first;
        }
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setAddress(address);
}

void SendCoinsDialog::pasteEntry(const SendCoinsRecipient &rv)
{
    if(!fNewRecipientAllowed)
        return;

    SendCoinsEntry *entry = nullptr;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        SendCoinsEntry *first = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(0)->widget());
        if(first->isClear())
        {
            entry = first;
        }
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setValue(rv);
    updateTabsAndLabels();
}

bool SendCoinsDialog::handlePaymentRequest(const SendCoinsRecipient &rv)
{
    // Check that we can accept new recipients before pasting
    if (!fNewRecipientAllowed)
        return false;
    pasteEntry(rv);
    return true;
}

void SendCoinsDialog::setBalance(const interfaces::WalletBalances& balances)
{
    if(model && model->getOptionsModel())
    {
        CAmount balance = 0;
        if (model->wallet().hasExternalSigner()) {
            ui->labelBalanceName->setText(tr("External balance:"));
        } else if (model->wallet().isLegacy() && model->wallet().privateKeysDisabled()) {
            balance = balances.watch_only_balance;
            ui->labelBalanceName->setText(tr("Watch-only balance:"));
        } else {
            balance = balances.balance;
        }

        const BitcoinUnit unit = model->getOptionsModel()->getDisplayUnit();
        const CAmount shielded = shieldedAvailableBalance(/*selected_only=*/false);
        ui->radioPayFromTransparent->setText(tr("Tra&nsparent (%1)").arg(BitcoinUnits::formatWithUnit(unit, balance)));
        ui->radioPayFromShielded->setText(tr("S&hielded (%1)").arg(BitcoinUnits::formatWithUnit(unit, shielded)));
        ui->labelBalance->setText(BitcoinUnits::formatWithUnit(unit, payFromShielded() ? shielded : balance));
    }
}

void SendCoinsDialog::updateDisplayUnit()
{
    setBalance(model->wallet().getBalances());
    coinControlUpdateLabels();
    ui->customFee->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    updateSmartFeeLabel();
}

void SendCoinsDialog::processSendCoinsReturn(const WalletModel::SendCoinsReturn &sendCoinsReturn, const QString &msgArg)
{
    QPair<QString, CClientUIInterface::MessageBoxFlags> msgParams;
    // Default to a warning message, override if error message is needed
    msgParams.second = CClientUIInterface::MSG_WARNING;

    // This comment is specific to SendCoinsDialog usage of WalletModel::SendCoinsReturn.
    // All status values are used only in WalletModel::prepareTransaction()
    switch(sendCoinsReturn.status)
    {
    case WalletModel::InvalidAddress:
        msgParams.first = tr("The recipient address is not valid. Please recheck.");
        break;
    case WalletModel::InvalidAmount:
        msgParams.first = tr("The amount to pay must be larger than 0.");
        break;
    case WalletModel::AmountExceedsBalance:
        msgParams.first = tr("The amount exceeds your balance.");
        break;
    case WalletModel::AmountWithFeeExceedsBalance:
        msgParams.first = tr("The total exceeds your balance when the %1 transaction fee is included.").arg(msgArg);
        break;
    case WalletModel::TransactionCreationFailed:
        msgParams.first = tr("Transaction creation failed!");
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    case WalletModel::AbsurdFee:
        msgParams.first = tr("A fee higher than %1 is considered an absurdly high fee.").arg(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), model->wallet().getDefaultMaxTxFee()));
        break;
    // included to prevent a compiler warning.
    case WalletModel::DuplicateAddress:
    case WalletModel::OK:
    default:
        return;
    }

    Q_EMIT message(tr("Send Coins"), msgParams.first, msgParams.second);
}

void SendCoinsDialog::minimizeFeeSection(bool fMinimize)
{
    ui->labelFeeMinimized->setVisible(fMinimize);
    ui->buttonChooseFee  ->setVisible(fMinimize);
    ui->buttonMinimizeFee->setVisible(!fMinimize);
    ui->frameFeeSelection->setVisible(!fMinimize);
    ui->horizontalLayoutSmartFee->setContentsMargins(0, (fMinimize ? 0 : 6), 0, 0);
    fFeeMinimized = fMinimize;
}

void SendCoinsDialog::on_buttonChooseFee_clicked()
{
    minimizeFeeSection(false);
}

void SendCoinsDialog::on_buttonMinimizeFee_clicked()
{
    updateFeeMinimizedLabel();
    minimizeFeeSection(true);
}

void SendCoinsDialog::useAvailableBalance(SendCoinsEntry* entry)
{
    // Include watch-only for wallets without private key
    m_coin_control->fAllowWatchOnly = model->wallet().privateKeysDisabled() && !model->wallet().hasExternalSigner();

    // Calculate available amount to send.
    CAmount amount = payFromShielded() ? shieldedAvailableBalance(/*selected_only=*/!m_selected_notes.empty())
                                       : model->wallet().getAvailableBalance(*m_coin_control);
    for (int i = 0; i < ui->entries->count(); ++i) {
        SendCoinsEntry* e = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if (e && !e->isHidden() && e != entry) {
            amount -= e->getValue().amount;
        }
    }

    if (amount > 0) {
      entry->checkSubtractFeeFromAmount();
      entry->setAmount(amount);
    } else {
      entry->setAmount(0);
    }
}

void SendCoinsDialog::updateFeeSectionControls()
{
    ui->confTargetSelector      ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee           ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee2          ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee3          ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelFeeEstimation      ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelCustomFeeWarning   ->setEnabled(ui->radioCustomFee->isChecked());
    ui->labelCustomPerKilobyte  ->setEnabled(ui->radioCustomFee->isChecked());
    ui->customFee               ->setEnabled(ui->radioCustomFee->isChecked());
}

void SendCoinsDialog::updateFeeMinimizedLabel()
{
    if(!model || !model->getOptionsModel())
        return;

    if (m_shielded_fee_mode) {
        ui->labelFeeMinimized->setText(shieldedFeeText());
        ui->labelFeeMinimized->setToolTip(tr("Shielded transactions pay a fixed fee of %1, plus %2 for each shielded input (note spent) and each shielded output (at least two). The fee selection does not apply to them.")
            .arg(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), SAPLING_BASE_FEE),
                 BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), SAPLING_PER_SPEND_FEE)));
        return;
    }
    ui->labelFeeMinimized->setToolTip(QString());

    if (ui->radioSmartFee->isChecked())
        ui->labelFeeMinimized->setText(ui->labelSmartFee->text());
    else {
        ui->labelFeeMinimized->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), ui->customFee->value()) + "/kB");
    }
}

void SendCoinsDialog::updateCoinControlState()
{
    if (ui->radioCustomFee->isChecked()) {
        m_coin_control->m_feerate = CFeeRate(ui->customFee->value());
    } else {
        m_coin_control->m_feerate.reset();
    }
    // Avoid using global defaults when sending money from the GUI
    // Either custom fee will be used or if not selected, the confirmation target from dropdown box
    m_coin_control->m_confirm_target = getConfTargetForIndex(ui->confTargetSelector->currentIndex());
    // Include watch-only for wallets without private key
    m_coin_control->fAllowWatchOnly = model->wallet().privateKeysDisabled() && !model->wallet().hasExternalSigner();
}

void SendCoinsDialog::updateNumberOfBlocks(int count, const QDateTime& blockDate, const QString& blockHash, double nVerificationProgress, bool header, SynchronizationState sync_state) {
    if (sync_state == SynchronizationState::POST_INIT) {
        updateSmartFeeLabel();
    }
}

void SendCoinsDialog::updateSmartFeeLabel()
{
    if(!model || !model->getOptionsModel())
        return;
    updateCoinControlState();
    m_coin_control->m_feerate.reset(); // Explicitly use only fee estimation rate for smart fee labels
    int returned_target;
    FeeReason reason;
    CFeeRate feeRate = CFeeRate(model->wallet().getMinimumFee(1000, *m_coin_control, &returned_target, &reason));

    ui->labelSmartFee->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), feeRate.GetFeePerK()) + "/kB");

    if (reason == FeeReason::FALLBACK) {
        ui->labelSmartFee2->show(); // (Smart fee not initialized yet. This usually takes a few blocks...)
        ui->labelFeeEstimation->setText("");
        ui->fallbackFeeWarningLabel->setVisible(!m_shielded_fee_mode);
    }
    else
    {
        ui->labelSmartFee2->hide();
        ui->labelFeeEstimation->setText(tr("Estimated to begin confirmation within %n block(s).", "", returned_target));
        ui->fallbackFeeWarningLabel->setVisible(false);
    }

    updateFeeMinimizedLabel();
}

// Coin Control: copy label "Quantity" to clipboard
void SendCoinsDialog::coinControlClipboardQuantity()
{
    GUIUtil::setClipboard(ui->labelCoinControlQuantity->text());
}

// Coin Control: copy label "Amount" to clipboard
void SendCoinsDialog::coinControlClipboardAmount()
{
    GUIUtil::setClipboard(ui->labelCoinControlAmount->text().left(ui->labelCoinControlAmount->text().indexOf(" ")));
}

// Coin Control: copy label "Fee" to clipboard
void SendCoinsDialog::coinControlClipboardFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlFee->text().left(ui->labelCoinControlFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "After fee" to clipboard
void SendCoinsDialog::coinControlClipboardAfterFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlAfterFee->text().left(ui->labelCoinControlAfterFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Bytes" to clipboard
void SendCoinsDialog::coinControlClipboardBytes()
{
    GUIUtil::setClipboard(ui->labelCoinControlBytes->text().replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Change" to clipboard
void SendCoinsDialog::coinControlClipboardChange()
{
    GUIUtil::setClipboard(ui->labelCoinControlChange->text().left(ui->labelCoinControlChange->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: settings menu - coin control enabled/disabled by user
void SendCoinsDialog::coinControlFeatureChanged(bool checked)
{
    ui->frameCoinControl->setVisible(checked);

    if (!checked && model) { // coin control features disabled
        m_coin_control = std::make_unique<CCoinControl>(m_coin_control->nCoinType);
        m_selected_notes.clear();
    }

    coinControlUpdateLabels();
}

// Coin Control: button inputs -> show actual coin control dialog
void SendCoinsDialog::coinControlButtonClicked()
{
    auto dlg = new CoinControlDialog(*m_coin_control, model, payFromShielded() ? &m_selected_notes : nullptr);
    connect(dlg, &QDialog::finished, this, &SendCoinsDialog::coinControlUpdateLabels);
    GUIUtil::ShowModalDialogAsynchronously(dlg);
}

// Coin Control: checkbox custom change address
void SendCoinsDialog::coinControlChangeChecked(int state)
{
    if (state == Qt::Unchecked && !fKeepChangeAddress)
    {
        m_coin_control->destChange = CNoDestination();
        ui->labelCoinControlChangeLabel->clear();
    }
    else
        // use this to re-validate an already entered address
        coinControlChangeEdited(ui->lineEditCoinControlChange->text());

    ui->lineEditCoinControlChange->setEnabled(state == Qt::Checked || fKeepChangeAddress);
}

// Coin Control: custom change address changed
void SendCoinsDialog::coinControlChangeEdited(const QString& text)
{
    if (model && model->getAddressTableModel())
    {
        // Default to no change address until verified
        m_coin_control->destChange = CNoDestination();
        ui->labelCoinControlChangeLabel->setStyleSheet(GUIUtil::getThemedStyleQString(GUIUtil::ThemedStyle::TS_ERROR));

        const CTxDestination dest = DecodeDestination(text.toStdString());

        if (text.isEmpty()) // Nothing entered
        {
            ui->labelCoinControlChangeLabel->setText("");
        }
        else if (!IsValidDestination(dest)) // Invalid address
        {
            ui->labelCoinControlChangeLabel->setText(tr("Warning: Invalid Kerrigan address"));
        }
        else // Valid address
        {
            if (!model->wallet().isSpendable(dest)) {
                ui->labelCoinControlChangeLabel->setText(tr("Warning: Unknown change address"));

                // confirmation dialog
                QMessageBox::StandardButton btnRetVal = QMessageBox::question(this, tr("Confirm custom change address"), tr("The address you selected for change is not part of this wallet. Any or all funds in your wallet may be sent to this address. Are you sure?"),
                    QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);

                if(btnRetVal == QMessageBox::Yes)
                    m_coin_control->destChange = dest;
                else
                {
                    ui->lineEditCoinControlChange->setText("");
                    ui->labelCoinControlChangeLabel->setStyleSheet(GUIUtil::getThemedStyleQString(GUIUtil::ThemedStyle::TS_PRIMARY));
                    ui->labelCoinControlChangeLabel->setText("");
                }
            }
            else // Known change address
            {
                ui->labelCoinControlChangeLabel->setStyleSheet(GUIUtil::getThemedStyleQString(GUIUtil::ThemedStyle::TS_PRIMARY));

                // Query label
                QString associatedLabel = model->getAddressTableModel()->labelForAddress(text);
                if (!associatedLabel.isEmpty())
                    ui->labelCoinControlChangeLabel->setText(associatedLabel);
                else
                    ui->labelCoinControlChangeLabel->setText(tr("(no label)"));

                m_coin_control->destChange = dest;
            }
        }
    }
}

// Coin Control: update labels
void SendCoinsDialog::coinControlUpdateLabels()
{
    if (!model || !model->getOptionsModel())
        return;

    updateCoinControlState();

    // set pay amounts
    CoinControlDialog::payAmounts.clear();
    CoinControlDialog::fSubtractFeeFromAmount = false;
    CoinControlDialog::fShieldedTx = isShieldedSend();
    CoinControlDialog::nShieldedOutputs = 0;

    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry && !entry->isHidden())
        {
            SendCoinsRecipient rcp = entry->getValue();
            CoinControlDialog::payAmounts.append(rcp.amount);
            if (rcp.fSubtractFeeFromAmount)
                CoinControlDialog::fSubtractFeeFromAmount = true;
            sapling::SaplingPaymentAddress addr;
            if (DecodeSaplingAddress(rcp.address.toStdString(), addr))
                CoinControlDialog::nShieldedOutputs++;
        }
    }

    if (m_shielded_fee_mode) {
        m_shielded_fee_timer.start();
    }

    if (payFromShielded() ? !m_selected_notes.empty() : m_coin_control->HasSelected())
    {
        // actual coin control calculation
        if (payFromShielded()) {
            CoinControlDialog::updateNoteLabels(m_selected_notes, model, this);
        } else {
            CoinControlDialog::updateLabels(*m_coin_control, model, this);
        }

        // show coin control stats
        ui->labelCoinControlAutomaticallySelected->hide();
        ui->widgetCoinControl->show();
    }
    else
    {
        // hide coin control stats
        ui->labelCoinControlAutomaticallySelected->show();
        ui->widgetCoinControl->hide();
        ui->labelCoinControlInsuffFunds->hide();
    }
}

// Settings menu - keep change address enabled/disabled by user
void SendCoinsDialog::keepChangeAddressChanged(bool checked)
{
    fKeepChangeAddress = checked;
}

void SendCoinsDialog::payFromChanged()
{
    if (!model) return;
    setBalance(model->wallet().getBalances());
    updateShieldedState();
}

void SendCoinsDialog::updateShieldedState()
{
    // Shielded transactions pay the fixed Sapling fee: show it in place of
    // the fee selection, which does not apply to them
    const bool shielded_send = isShieldedSend();
    if (shielded_send != m_shielded_fee_mode) {
        m_shielded_fee_mode = shielded_send;
        if (shielded_send) {
            ui->labelFeeMinimized->setVisible(true);
            ui->buttonChooseFee->setVisible(false);
            ui->buttonMinimizeFee->setVisible(false);
            ui->frameFeeSelection->setVisible(false);
            ui->fallbackFeeWarningLabel->setVisible(false);
            updateFeeMinimizedLabel();
        } else {
            m_shielded_fee_timer.stop();
            minimizeFeeSection(fFeeMinimized);
            updateSmartFeeLabel();
        }
    }

    // Change from shielded notes always goes to an internal shielded address
    const bool shielded_source = payFromShielded();
    ui->checkBoxCoinControlChange->setEnabled(!shielded_source);
    ui->checkBoxCoinControlChange->setToolTip(shielded_source
        ? tr("Shielded change always goes to an internal shielded address of this wallet, so it cannot be linked to your published addresses.")
        : m_change_address_tooltip);
    ui->lineEditCoinControlChange->setEnabled(!shielded_source && (ui->checkBoxCoinControlChange->isChecked() || fKeepChangeAddress));

    coinControlUpdateLabels();
}

SendConfirmationDialog::SendConfirmationDialog(const QString& title, const QString& text, const QString& informative_text, const QString& detailed_text, int _secDelay, bool enable_send, bool always_show_unsigned, QWidget* parent)
    : QMessageBox(parent), secDelay(_secDelay), m_enable_send(enable_send)
{
    GUIUtil::updateFonts();
    setIcon(QMessageBox::Question);
    setWindowTitle(title); // On macOS, the window title is ignored (as required by the macOS Guidelines).
    setText(text);
    setInformativeText(informative_text);
    setDetailedText(detailed_text);
    setStandardButtons(QMessageBox::Yes | QMessageBox::Cancel);
    if (always_show_unsigned || !enable_send) addButton(QMessageBox::Save);
    setDefaultButton(QMessageBox::Cancel);
    yesButton = button(QMessageBox::Yes);
    if (confirmButtonText.isEmpty()) {
        confirmButtonText = yesButton->text();
    }
    m_psbt_button = button(QMessageBox::Save);
    updateButtons();
    connect(&countDownTimer, &QTimer::timeout, this, &SendConfirmationDialog::countDown);
}

int SendConfirmationDialog::exec()
{
    updateButtons();
    countDownTimer.start(1s);
    return QMessageBox::exec();
}

void SendConfirmationDialog::countDown()
{
    secDelay--;
    updateButtons();

    if(secDelay <= 0)
    {
        countDownTimer.stop();
    }
}

void SendConfirmationDialog::updateButtons()
{
    if(secDelay > 0)
    {
        yesButton->setEnabled(false);
        yesButton->setText(confirmButtonText + (m_enable_send ? (" (" + QString::number(secDelay) + ")") : QString("")));
        if (m_psbt_button) {
            m_psbt_button->setEnabled(false);
            m_psbt_button->setText(m_psbt_button_text + " (" + QString::number(secDelay) + ")");
        }
    }
    else
    {
        yesButton->setEnabled(m_enable_send);
        yesButton->setText(confirmButtonText);
        if (m_psbt_button) {
            m_psbt_button->setEnabled(true);
            m_psbt_button->setText(m_psbt_button_text);
        }
    }
}

