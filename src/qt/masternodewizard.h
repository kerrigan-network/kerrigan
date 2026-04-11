// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KERRIGAN_QT_MASTERNODEWIZARD_H
#define KERRIGAN_QT_MASTERNODEWIZARD_H

#include <QComboBox>
#include <QDialog>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QSpinBox>
#include <QStackedWidget>
#include <QTextEdit>

class WalletModel;

/** Masternode deployment wizard dialog.
 *
 *  Five-page QStackedWidget flow:
 *    0 -- Type selection (Regular / BroodNode)
 *    1 -- Collateral location or creation
 *    2 -- Service address & BLS key generation
 *    3 -- Owner / voting / payout addresses
 *    4 -- Review & submit (protx register)
 */
class MasternodeWizard : public QDialog
{
    Q_OBJECT

public:
    explicit MasternodeWizard(WalletModel* walletModel, QWidget* parent = nullptr);
    ~MasternodeWizard() override;

private Q_SLOTS:
    void onNextClicked();
    void onBackClicked();

    // Page 1 -- collateral
    void onLocateCollateral();
    void onCreateCollateral();

    // Page 2 -- service & keys
    void onGenerateBLSKeys();
    void onToggleSecretVisibility();

    // Page 4 -- submit
    void onRegisterMasternode();

private:
    WalletModel* m_walletModel;
    QStackedWidget* m_stack{nullptr};

    // Navigation
    QPushButton* m_btnBack{nullptr};
    QPushButton* m_btnNext{nullptr};

    // --- Page 0: Type ---
    QRadioButton* m_radioRegular{nullptr};
    QRadioButton* m_radioBrood{nullptr};

    // --- Page 1: Collateral ---
    QComboBox* m_comboCollateral{nullptr};
    QLabel* m_labelCollateralStatus{nullptr};
    QPushButton* m_btnLocate{nullptr};
    QPushButton* m_btnCreateCollateral{nullptr};

    // --- Page 2: Service & Keys ---
    QLineEdit* m_editIP{nullptr};
    QLineEdit* m_editPort{nullptr};
    QPushButton* m_btnGenerateBLS{nullptr};
    QLineEdit* m_editOperatorPubKey{nullptr};
    QLineEdit* m_editOperatorSecret{nullptr};
    QPushButton* m_btnToggleSecret{nullptr};
    QPushButton* m_btnCopySecret{nullptr};

    // --- Page 3: Addresses ---
    QLineEdit* m_editOwnerAddr{nullptr};
    QLineEdit* m_editVotingAddr{nullptr};
    QLineEdit* m_editPayoutAddr{nullptr};
    QSpinBox* m_spinOperatorReward{nullptr};

    // --- Page 4: Review ---
    QTextEdit* m_reviewBrowser{nullptr};
    QLabel* m_labelFee{nullptr};
    QPushButton* m_btnRegister{nullptr};

    // State
    bool m_useExistingCollateral{false};   // true when "Locate" found a UTXO
    QString m_collateralTxid;
    int m_collateralIndex{-1};
    QString m_collateralAddress;

    // Helpers
    int requiredCollateral() const;
    QWidget* createPageType();
    QWidget* createPageCollateral();
    QWidget* createPageService();
    QWidget* createPageAddresses();
    QWidget* createPageReview();

    void buildReviewSummary();
    bool validateCurrentPage();

    /** Build wallet URI for RPC calls routed to the correct wallet. */
    std::string walletUri() const;
};

#endif // KERRIGAN_QT_MASTERNODEWIZARD_H
