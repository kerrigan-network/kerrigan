// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/masternodewizard.h>

#include <interfaces/node.h>

#include <qt/guiutil.h>
#include <qt/guiutil_font.h>
#include <qt/walletmodel.h>

#include <QApplication>
#include <QClipboard>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QUrl>
#include <QVBoxLayout>

#include <univalue.h>

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

MasternodeWizard::MasternodeWizard(WalletModel* walletModel, QWidget* parent)
    : QDialog(parent),
      m_walletModel(walletModel)
{
    setWindowTitle(tr("Deploy New Masternode"));
    setMinimumSize(620, 520);

    auto* mainLayout = new QVBoxLayout(this);

    m_stack = new QStackedWidget(this);
    m_stack->addWidget(createPageType());
    m_stack->addWidget(createPageCollateral());
    m_stack->addWidget(createPageService());
    m_stack->addWidget(createPageAddresses());
    m_stack->addWidget(createPageReview());
    mainLayout->addWidget(m_stack, 1);

    // Navigation bar
    auto* navLayout = new QHBoxLayout;
    navLayout->addStretch();
    m_btnBack = new QPushButton(tr("Back"), this);
    m_btnNext = new QPushButton(tr("Next"), this);
    navLayout->addWidget(m_btnBack);
    navLayout->addWidget(m_btnNext);
    mainLayout->addLayout(navLayout);

    m_btnBack->setEnabled(false);

    connect(m_btnBack, &QPushButton::clicked, this, &MasternodeWizard::onBackClicked);
    connect(m_btnNext, &QPushButton::clicked, this, &MasternodeWizard::onNextClicked);

    GUIUtil::updateFonts();
}

MasternodeWizard::~MasternodeWizard() = default;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

int MasternodeWizard::requiredCollateral() const
{
    return m_radioBrood && m_radioBrood->isChecked() ? 40000 : 10000;
}

std::string MasternodeWizard::walletUri() const
{
    if (!m_walletModel) return {};
    QByteArray encoded = QUrl::toPercentEncoding(m_walletModel->getWalletName());
    return "/wallet/" + std::string(encoded.constData(), encoded.length());
}

// ---------------------------------------------------------------------------
// Page factories
// ---------------------------------------------------------------------------

QWidget* MasternodeWizard::createPageType()
{
    auto* page = new QWidget(this);
    auto* layout = new QVBoxLayout(page);

    auto* title = new QLabel(tr("<h3>Select Masternode Type</h3>"), page);
    layout->addWidget(title);

    m_radioRegular = new QRadioButton(tr("Regular Masternode (10,000 KRGN)"), page);
    m_radioBrood = new QRadioButton(tr("BroodNode (40,000 KRGN) -- coming soon"), page);
    m_radioRegular->setChecked(true);
    m_radioBrood->setEnabled(false);

    layout->addWidget(m_radioRegular);
    layout->addWidget(m_radioBrood);

    auto* info = new QLabel(
        tr("A <b>Regular Masternode</b> requires exactly 10,000 KRGN collateral."),
        page);
    info->setWordWrap(true);
    layout->addWidget(info);

    layout->addStretch();
    return page;
}

QWidget* MasternodeWizard::createPageCollateral()
{
    auto* page = new QWidget(this);
    auto* layout = new QVBoxLayout(page);

    auto* title = new QLabel(tr("<h3>Collateral</h3>"), page);
    layout->addWidget(title);

    auto* desc = new QLabel(
        tr("Locate an existing collateral UTXO in your wallet, or create a new one."),
        page);
    desc->setWordWrap(true);
    layout->addWidget(desc);

    // Locate
    auto* locateLayout = new QHBoxLayout;
    m_btnLocate = new QPushButton(tr("Locate Collateral"), page);
    locateLayout->addWidget(m_btnLocate);
    locateLayout->addStretch();
    layout->addLayout(locateLayout);

    m_comboCollateral = new QComboBox(page);
    m_comboCollateral->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    layout->addWidget(m_comboCollateral);

    m_labelCollateralStatus = new QLabel(page);
    m_labelCollateralStatus->setWordWrap(true);
    layout->addWidget(m_labelCollateralStatus);

    // Separator
    auto* orLabel = new QLabel(tr("<b>- or -</b>"), page);
    orLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(orLabel);

    // Create collateral
    m_btnCreateCollateral = new QPushButton(tr("Create Collateral Transaction"), page);
    layout->addWidget(m_btnCreateCollateral);

    auto* warning = new QLabel(
        tr("<i>Creating collateral sends the exact amount to a new address in your wallet. "
           "The transaction requires %1 confirmations before you can register.</i>")
            .arg(15),
        page);
    warning->setWordWrap(true);
    layout->addWidget(warning);

    layout->addStretch();

    connect(m_btnLocate, &QPushButton::clicked, this, &MasternodeWizard::onLocateCollateral);
    connect(m_btnCreateCollateral, &QPushButton::clicked, this, &MasternodeWizard::onCreateCollateral);

    return page;
}

QWidget* MasternodeWizard::createPageService()
{
    auto* page = new QWidget(this);
    auto* layout = new QVBoxLayout(page);

    auto* title = new QLabel(tr("<h3>Service Address &amp; Keys</h3>"), page);
    layout->addWidget(title);

    auto* form = new QFormLayout;

    // IP address
    m_editIP = new QLineEdit(page);
    m_editIP->setPlaceholderText(tr("e.g. 203.0.113.45"));
    auto* ipValidator = new QRegularExpressionValidator(
        QRegularExpression(
            R"(^((25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(25[0-5]|2[0-4]\d|[01]?\d?\d)$)"),
        m_editIP);
    m_editIP->setValidator(ipValidator);
    form->addRow(tr("IP Address:"), m_editIP);

    // Port
    m_editPort = new QLineEdit("7120", page);
    m_editPort->setMaximumWidth(80);
    auto* portValidator = new QRegularExpressionValidator(
        QRegularExpression(R"(^[1-9]\d{0,4}$)"), m_editPort);
    m_editPort->setValidator(portValidator);
    form->addRow(tr("Port:"), m_editPort);

    layout->addLayout(form);

    // BLS
    auto* blsGroup = new QGroupBox(tr("BLS Operator Keys"), page);
    auto* blsLayout = new QVBoxLayout(blsGroup);

    auto* blsHint = new QLabel(
        tr("Paste keys from your masternode host, or generate a new pair:"),
        blsGroup);
    blsHint->setWordWrap(true);
    blsLayout->addWidget(blsHint);

    m_btnGenerateBLS = new QPushButton(tr("Generate New BLS Keys"), blsGroup);
    blsLayout->addWidget(m_btnGenerateBLS);

    auto* pubForm = new QFormLayout;
    m_editOperatorPubKey = new QLineEdit(blsGroup);
    m_editOperatorPubKey->setPlaceholderText(tr("Operator public key (hex) -- paste or generate"));
    pubForm->addRow(tr("Public Key:"), m_editOperatorPubKey);

    m_editOperatorSecret = new QLineEdit(blsGroup);
    m_editOperatorSecret->setEchoMode(QLineEdit::Password);
    m_editOperatorSecret->setPlaceholderText(tr("Operator secret key (hex) -- paste or generate"));

    auto* secretRow = new QHBoxLayout;
    secretRow->addWidget(m_editOperatorSecret, 1);

    m_btnToggleSecret = new QPushButton(tr("Show"), blsGroup);
    m_btnToggleSecret->setMaximumWidth(60);
    secretRow->addWidget(m_btnToggleSecret);

    m_btnCopySecret = new QPushButton(tr("Copy"), blsGroup);
    m_btnCopySecret->setMaximumWidth(60);
    secretRow->addWidget(m_btnCopySecret);

    pubForm->addRow(tr("Secret Key:"), secretRow);
    blsLayout->addLayout(pubForm);

    auto* secretWarning = new QLabel(
        tr("<span style=\"color: #d4a017;\">Save your operator private key securely. "
           "You will need it on your masternode server.</span>"),
        blsGroup);
    secretWarning->setWordWrap(true);
    blsLayout->addWidget(secretWarning);

    layout->addWidget(blsGroup);
    layout->addStretch();

    connect(m_btnGenerateBLS, &QPushButton::clicked, this, &MasternodeWizard::onGenerateBLSKeys);
    connect(m_btnToggleSecret, &QPushButton::clicked, this, &MasternodeWizard::onToggleSecretVisibility);
    connect(m_btnCopySecret, &QPushButton::clicked, this, [this]() {
        QApplication::clipboard()->setText(m_editOperatorSecret->text());
    });

    return page;
}

QWidget* MasternodeWizard::createPageAddresses()
{
    auto* page = new QWidget(this);
    auto* layout = new QVBoxLayout(page);

    auto* title = new QLabel(tr("<h3>Addresses</h3>"), page);
    layout->addWidget(title);

    auto* desc = new QLabel(
        tr("These addresses are auto-generated from your wallet. "
           "You may override them with custom addresses if needed."),
        page);
    desc->setWordWrap(true);
    layout->addWidget(desc);

    auto* form = new QFormLayout;

    m_editOwnerAddr = new QLineEdit(page);
    m_editOwnerAddr->setPlaceholderText(tr("Owner address"));
    form->addRow(tr("Owner Address:"), m_editOwnerAddr);

    m_editVotingAddr = new QLineEdit(page);
    m_editVotingAddr->setPlaceholderText(tr("Voting address (defaults to owner)"));
    form->addRow(tr("Voting Address:"), m_editVotingAddr);

    m_editPayoutAddr = new QLineEdit(page);
    m_editPayoutAddr->setPlaceholderText(tr("Payout address"));
    form->addRow(tr("Payout Address:"), m_editPayoutAddr);

    m_spinOperatorReward = new QSpinBox(page);
    m_spinOperatorReward->setRange(0, 100);
    m_spinOperatorReward->setValue(0);
    m_spinOperatorReward->setSuffix("%");
    form->addRow(tr("Operator Reward:"), m_spinOperatorReward);

    layout->addLayout(form);
    layout->addStretch();

    return page;
}

QWidget* MasternodeWizard::createPageReview()
{
    auto* page = new QWidget(this);
    auto* layout = new QVBoxLayout(page);

    auto* title = new QLabel(tr("<h3>Review &amp; Register</h3>"), page);
    layout->addWidget(title);

    m_reviewBrowser = new QTextEdit(page);
    m_reviewBrowser->setReadOnly(true);
    layout->addWidget(m_reviewBrowser, 1);

    m_labelFee = new QLabel(page);
    layout->addWidget(m_labelFee);

    m_btnRegister = new QPushButton(tr("Register Masternode"), page);
    m_btnRegister->setStyleSheet("QPushButton { font-weight: bold; padding: 8px; }");
    layout->addWidget(m_btnRegister);

    connect(m_btnRegister, &QPushButton::clicked, this, &MasternodeWizard::onRegisterMasternode);

    return page;
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

void MasternodeWizard::onNextClicked()
{
    if (!validateCurrentPage()) return;

    int next = m_stack->currentIndex() + 1;

    // On entering page 3 (Addresses), auto-generate addresses if empty
    if (next == 3) {
        try {
            if (m_editOwnerAddr->text().trimmed().isEmpty()) {
                UniValue params(UniValue::VARR);
                params.push_back("owner_" + std::to_string(requiredCollateral()));
                UniValue result = m_walletModel->node().executeRpc("getnewaddress", params, walletUri());
                m_editOwnerAddr->setText(QString::fromStdString(result.get_str()));
            }
            if (m_editVotingAddr->text().trimmed().isEmpty()) {
                m_editVotingAddr->setText(m_editOwnerAddr->text());
            }
            if (m_editPayoutAddr->text().trimmed().isEmpty()) {
                UniValue params(UniValue::VARR);
                params.push_back("payout_mn");
                UniValue result = m_walletModel->node().executeRpc("getnewaddress", params, walletUri());
                m_editPayoutAddr->setText(QString::fromStdString(result.get_str()));
            }
        } catch (const std::exception& e) {
            QMessageBox::warning(this, tr("Address Generation Failed"),
                                 tr("Could not generate addresses: %1").arg(QString::fromStdString(e.what())));
        }
    }

    // On entering page 4 (Review), build summary
    if (next == 4) {
        buildReviewSummary();
    }

    if (next < m_stack->count()) {
        m_stack->setCurrentIndex(next);
        m_btnBack->setEnabled(true);
        if (next == m_stack->count() - 1) {
            m_btnNext->setEnabled(false);
        }
    }
}

void MasternodeWizard::onBackClicked()
{
    int prev = m_stack->currentIndex() - 1;
    if (prev >= 0) {
        m_stack->setCurrentIndex(prev);
        m_btnNext->setEnabled(true);
        m_btnBack->setEnabled(prev > 0);
    }
}

bool MasternodeWizard::validateCurrentPage()
{
    switch (m_stack->currentIndex()) {
    case 0: // Type -- always valid, one radio is always selected
        return true;

    case 1: { // Collateral
        if (m_comboCollateral->count() == 0 || m_comboCollateral->currentIndex() < 0) {
            QMessageBox::warning(this, tr("No Collateral"),
                                 tr("Please locate or create a collateral transaction before proceeding."));
            return false;
        }
        return true;
    }

    case 2: { // Service & Keys
        if (m_editIP->text().trimmed().isEmpty()) {
            QMessageBox::warning(this, tr("Missing IP Address"),
                                 tr("Please enter the IP address of your masternode server."));
            return false;
        }
        if (!m_editIP->hasAcceptableInput()) {
            QMessageBox::warning(this, tr("Invalid IP Address"),
                                 tr("Please enter a valid IPv4 address."));
            return false;
        }
        if (m_editPort->text().trimmed().isEmpty()) {
            QMessageBox::warning(this, tr("Missing Port"),
                                 tr("Please enter the service port."));
            return false;
        }
        if (m_editOperatorPubKey->text().trimmed().isEmpty()) {
            QMessageBox::warning(this, tr("Missing BLS Key"),
                                 tr("Please generate or enter a BLS operator public key."));
            return false;
        }
        return true;
    }

    case 3: { // Addresses
        if (m_editOwnerAddr->text().trimmed().isEmpty()) {
            QMessageBox::warning(this, tr("Missing Owner Address"),
                                 tr("Owner address is required."));
            return false;
        }
        if (m_editPayoutAddr->text().trimmed().isEmpty()) {
            QMessageBox::warning(this, tr("Missing Payout Address"),
                                 tr("Payout address is required."));
            return false;
        }
        return true;
    }

    default:
        return true;
    }
}

// ---------------------------------------------------------------------------
// Page 1: Collateral
// ---------------------------------------------------------------------------

void MasternodeWizard::onLocateCollateral()
{
    if (!m_walletModel) return;

    m_comboCollateral->clear();
    m_useExistingCollateral = false;
    m_labelCollateralStatus->clear();

    try {
        // "masternode outputs" -- subcommand is part of the method name
        UniValue params(UniValue::VARR);
        UniValue result = m_walletModel->node().executeRpc("masternode outputs", params, walletUri());

        // masternode outputs returns an array of strings in "txid-index"
        // format (COutPoint::ToStringShort).
        int required = requiredCollateral();
        int found = 0;

        if (result.isArray()) {
            for (size_t i = 0; i < result.size(); ++i) {
                const UniValue& item = result[i];
                if (item.isStr()) {
                    // Format: "txid-index" -- split on last dash
                    QString outpointStr = QString::fromStdString(item.get_str());
                    int lastDash = outpointStr.lastIndexOf('-');
                    if (lastDash > 0) {
                        QString txid = outpointStr.left(lastDash);
                        QString idxStr = outpointStr.mid(lastDash + 1);
                        QString label = txid + ":" + idxStr;
                        m_comboCollateral->addItem(label);
                        ++found;
                    }
                }
            }
        }

        if (found > 0) {
            m_useExistingCollateral = true;
            m_labelCollateralStatus->setText(
                tr("Found %1 eligible collateral output(s).").arg(found));
            m_labelCollateralStatus->setStyleSheet("color: green;");
        } else {
            m_labelCollateralStatus->setText(
                tr("No eligible collateral found. You need exactly %1 KRGN in a single transaction output.")
                    .arg(required));
            m_labelCollateralStatus->setStyleSheet("color: red;");
        }
    } catch (const std::exception& e) {
        m_labelCollateralStatus->setText(
            tr("Error scanning wallet: %1").arg(QString::fromStdString(e.what())));
        m_labelCollateralStatus->setStyleSheet("color: red;");
    }
}

void MasternodeWizard::onCreateCollateral()
{
    if (!m_walletModel) return;

    int amount = requiredCollateral();

    if (QMessageBox::question(this, tr("Create Collateral"),
            tr("This will send exactly %1 KRGN to a new address in your wallet.\n\n"
               "The transaction must confirm before you can complete registration.\n\n"
               "Proceed?").arg(amount),
            QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }

    // Unlock wallet
    WalletModel::UnlockContext ctx(m_walletModel->requestUnlock());
    if (!ctx.isValid()) return;

    try {
        // getnewaddress for collateral
        UniValue addrParams(UniValue::VARR);
        addrParams.push_back("collateral_mn");
        UniValue addrResult = m_walletModel->node().executeRpc("getnewaddress", addrParams, walletUri());
        QString newAddr = QString::fromStdString(addrResult.get_str());

        // sendtoaddress
        UniValue sendParams(UniValue::VARR);
        sendParams.push_back(newAddr.toStdString());
        sendParams.push_back(amount);
        UniValue sendResult = m_walletModel->node().executeRpc("sendtoaddress", sendParams, walletUri());
        QString txid = QString::fromStdString(sendResult.get_str());

        // Add to combo
        m_comboCollateral->clear();
        // The output index for sendtoaddress result is typically 0 or 1,
        // but we store the address so register_fund can be used instead
        m_collateralAddress = newAddr;
        m_useExistingCollateral = false;
        m_comboCollateral->addItem(
            tr("%1 (new collateral to %2)").arg(txid).arg(newAddr));

        m_labelCollateralStatus->setText(
            tr("Collateral transaction sent: %1\n"
               "Wait for confirmations before registering.").arg(txid));
        m_labelCollateralStatus->setStyleSheet("color: green;");

        QMessageBox::information(this, tr("Collateral Created"),
            tr("Transaction %1 sent.\n\n"
               "Address: %2\n"
               "Amount: %3 KRGN\n\n"
               "Please wait for at least 15 confirmations before completing registration.")
                .arg(txid, newAddr).arg(amount));

    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Collateral Failed"),
                              QString::fromStdString(e.what()));
    }
}

// ---------------------------------------------------------------------------
// Page 2: BLS Keys
// ---------------------------------------------------------------------------

void MasternodeWizard::onGenerateBLSKeys()
{
    if (!m_walletModel) return;

    try {
        UniValue params(UniValue::VARR);
        UniValue result = m_walletModel->node().executeRpc("bls generate", params, walletUri());

        if (result.isObject()) {
            if (const auto& v = result.find_value("public"); v.isStr()) {
                m_editOperatorPubKey->setText(QString::fromStdString(v.get_str()));
            }
            if (const auto& v = result.find_value("secret"); v.isStr()) {
                m_editOperatorSecret->setText(QString::fromStdString(v.get_str()));
            }
        }
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("BLS Generation Failed"),
                              QString::fromStdString(e.what()));
    }
}

void MasternodeWizard::onToggleSecretVisibility()
{
    if (m_editOperatorSecret->echoMode() == QLineEdit::Password) {
        m_editOperatorSecret->setEchoMode(QLineEdit::Normal);
        m_btnToggleSecret->setText(tr("Hide"));
    } else {
        m_editOperatorSecret->setEchoMode(QLineEdit::Password);
        m_btnToggleSecret->setText(tr("Show"));
    }
}

// ---------------------------------------------------------------------------
// Page 4: Review & Submit
// ---------------------------------------------------------------------------

void MasternodeWizard::buildReviewSummary()
{
    QString html;
    html += "<html><body style='font-family: monospace;'>";

    html += "<h4>" + tr("Masternode Registration Summary") + "</h4>";
    html += "<table cellpadding='4'>";

    auto row = [&](const QString& label, const QString& value) {
        html += "<tr><td><b>" + label.toHtmlEscaped() + "</b></td>"
                "<td>" + value.toHtmlEscaped() + "</td></tr>";
    };

    row(tr("Type"), m_radioRegular->isChecked() ? tr("Regular (10,000 KRGN)") : tr("BroodNode (40,000 KRGN)"));

    bool hasExisting = m_comboCollateral->currentIndex() >= 0
                       && m_comboCollateral->currentText().contains(":");
    if (hasExisting) {
        row(tr("Collateral"), m_comboCollateral->currentText());
        row(tr("Registration Mode"), tr("protx register (existing UTXO)"));
    } else {
        row(tr("Registration Mode"), tr("protx register_fund (new collateral)"));
    }

    row(tr("Service"), m_editIP->text() + ":" + m_editPort->text());
    row(tr("Operator Public Key"), m_editOperatorPubKey->text());
    row(tr("Owner Address"), m_editOwnerAddr->text());
    row(tr("Voting Address"), m_editVotingAddr->text());
    row(tr("Payout Address"), m_editPayoutAddr->text());
    row(tr("Operator Reward"), QString::number(m_spinOperatorReward->value()) + "%");

    html += "</table>";
    html += "</body></html>";

    m_reviewBrowser->setHtml(html);
    m_labelFee->setText(tr("A small network fee will be deducted from your wallet balance."));
}

void MasternodeWizard::onRegisterMasternode()
{
    if (!m_walletModel) return;

    // Refresh summary to ensure it matches actual state
    buildReviewSummary();

    // Final confirmation
    if (QMessageBox::question(this, tr("Confirm Registration"),
            tr("Are you sure you want to register this masternode?\n\n"
               "This will submit a ProTx registration transaction to the network."),
            QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }

    // Unlock wallet
    WalletModel::UnlockContext ctx(m_walletModel->requestUnlock());
    if (!ctx.isValid()) return;

    try {
        UniValue params(UniValue::VARR);

        QString service = m_editIP->text() + ":" + m_editPort->text();
        QString operatorReward = QString::number(m_spinOperatorReward->value());
        QString votingAddr = m_editVotingAddr->text().trimmed();
        if (votingAddr.isEmpty()) {
            votingAddr = m_editOwnerAddr->text();
        }

        // coreP2PAddrs is an array parameter
        UniValue addrArr(UniValue::VARR);
        addrArr.push_back(service.toStdString());

        // Derive collateral mode from actual combo state (not flag -- avoids back/forward desync)
        bool hasExistingCollateral = m_comboCollateral->currentIndex() >= 0
                                     && m_comboCollateral->currentText().contains(":");
        if (hasExistingCollateral) {
            // protx register -- use existing collateral UTXO
            QString collateralStr = m_comboCollateral->currentText();
            QStringList parts = collateralStr.split(":");
            if (parts.size() < 2) {
                QMessageBox::critical(this, tr("Invalid Collateral"),
                    tr("Could not parse collateral transaction. Expected format: txid:index"));
                return;
            }
            QString collTxid = parts.value(0).trimmed();
            int collateralIdx = parts.value(1).split(" ").value(0).trimmed().toInt();

            // Find a fee source address with funds (NOT the collateral UTXO)
            QString feeSourceAddr;
            try {
                UniValue listParams(UniValue::VARR);
                UniValue utxos = m_walletModel->node().executeRpc("listunspent", listParams, walletUri());
                if (utxos.isArray()) {
                    for (size_t i = 0; i < utxos.size(); ++i) {
                        const UniValue& u = utxos[i];
                        std::string utxoTxid = u.find_value("txid").get_str();
                        int utxoVout = u.find_value("vout").getInt<int>();
                        // Skip the collateral UTXO itself
                        if (utxoTxid == collTxid.toStdString() && utxoVout == collateralIdx)
                            continue;
                        // Any other UTXO can fund the fee
                        feeSourceAddr = QString::fromStdString(u.find_value("address").get_str());
                        break;
                    }
                }
            } catch (...) {}

            if (feeSourceAddr.isEmpty()) {
                QMessageBox::critical(this, tr("No Fee Funds"),
                    tr("Your wallet needs a small additional UTXO (besides the collateral) to pay the registration fee.\n\n"
                       "Send a small amount (e.g., 1 KRGN) to any address in this wallet, then try again."));
                return;
            }

            params.push_back(collTxid.toStdString());          // collateralHash
            params.push_back(collateralIdx);                   // collateralIndex (int)
            params.push_back(addrArr);                         // coreP2PAddrs
            params.push_back(m_editOwnerAddr->text().toStdString());
            params.push_back(m_editOperatorPubKey->text().toStdString());
            params.push_back(votingAddr.toStdString());
            params.push_back(operatorReward.toStdString());
            params.push_back(m_editPayoutAddr->text().toStdString());
            params.push_back(feeSourceAddr.toStdString());     // feeSourceAddress (NOT collateral)
        } else {
            // protx register_fund -- subcommand is part of method name, NOT a param
            params.push_back(m_editOwnerAddr->text().toStdString());  // collateralAddress
            params.push_back(addrArr);                                // coreP2PAddrs
            params.push_back(m_editOwnerAddr->text().toStdString());  // ownerAddress
            params.push_back(m_editOperatorPubKey->text().toStdString());
            params.push_back(votingAddr.toStdString());
            params.push_back(operatorReward.toStdString());
            params.push_back(m_editPayoutAddr->text().toStdString());
        }

        // Method name includes subcommand: "protx register" or "protx register_fund"
        std::string rpcMethod = hasExistingCollateral ? "protx register" : "protx register_fund";
        UniValue result = m_walletModel->node().executeRpc(rpcMethod, params, walletUri());
        QString txid;
        if (result.isStr()) {
            txid = QString::fromStdString(result.get_str());
        } else {
            txid = QString::fromStdString(result.write(2));
        }

        QMessageBox::information(this, tr("Registration Successful"),
            tr("Your masternode has been registered!\n\n"
               "ProTx Hash: %1\n\n"
               "The masternode will appear in the list after the transaction confirms.\n\n"
               "Remember to configure your masternode server with the operator private key.")
                .arg(txid));

        accept(); // Close dialog on success

    } catch (const UniValue& e) {
        QString msg = tr("RPC error");
        if (e.isObject()) {
            const UniValue& msgVal = e.find_value("message");
            if (msgVal.isStr()) msg = QString::fromStdString(msgVal.get_str());
        } else if (e.isStr()) {
            msg = QString::fromStdString(e.get_str());
        }
        QMessageBox::critical(this, tr("Registration Failed"), msg);
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Registration Failed"),
                              QString::fromStdString(e.what()));
    } catch (...) {
        QMessageBox::critical(this, tr("Registration Failed"),
                              tr("An unexpected error occurred during registration."));
    }
}
