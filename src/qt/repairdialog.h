// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_REPAIRDIALOG_H
#define BITCOIN_QT_REPAIRDIALOG_H

#include <recovery/recovery.h>

#include <QDialog>
#include <QString>

#include <string>

class QCheckBox;
class QLabel;
class QLineEdit;
class QPushButton;

namespace interfaces {
class Node;
} // namespace interfaces

/**
 * Guided-repair dialog (WS-HEAL v2 8.2).
 *
 * Flow: shows the active diagnosis, runs a repairnode dry-run through the
 * node interface (plan + one-time confirm token), requires the user to type
 * a confirmation word, then arms the repair. Arming ONLY writes the repair
 * marker - this dialog never requests shutdown and the node interface it
 * uses has no shutdown parameter at all: the clean shutdown + relaunch is
 * owned by the caller (InitExecutor restart chain at runtime; the
 * BitcoinApplication crippled-wait release path at startup), because
 * BitcoinGUI::handleRestart refuses to restart once shutdown has been
 * requested.
 *
 * All human-readable copy lives here behind tr() (contract 7.1: the daemon
 * emits stable machine ids only). The static *Text() tables are shared with
 * the BitcoinGUI recovery banner.
 */
class RepairDialog : public QDialog
{
    Q_OBJECT

public:
    enum class Context {
        Runtime, //!< node fully initialized; caller drives handleRestart afterwards
        Startup, //!< crippled_wait: caller releases the parked init thread and relaunches
    };

    explicit RepairDialog(interfaces::Node& node, Context context, const QString& scope, QWidget* parent = nullptr);

    //! True once repairnode reported ARMED (or ALREADY_ARMED) and the dialog
    //! was accepted; the caller must then drive the restart.
    bool repairArmed() const { return m_armed; }

    //! Scope for the recommended action ("network" for guided network
    //! repair, "full" otherwise).
    static QString scopeForAction(recovery::RecommendedAction action);

    // ---- Front-end copy tables (shared with the BitcoinGUI banner) ----
    static QString modeText(recovery::DaemonMode mode);
    static QString findingText(recovery::FindingCode code);
    static QString actionText(recovery::RecommendedAction action);
    static QString phaseText(recovery::RepairPhase phase);
    //! Witness-rebuild progress. 0/0 means "count unavailable" (the daemon
    //! never fabricates progress) and is rendered as such - never "0 of 0",
    //! never a percentage.
    static QString witnessProgressText(int64_t rebuilt, int64_t total);

private Q_SLOTS:
    void refreshPlan();
    void onConfirmTextChanged(const QString& text);
    void onRepairClicked();

private:
    void populateStatus();

    interfaces::Node& m_node;
    const Context m_context;
    const QString m_scope;
    std::string m_token;
    bool m_armed{false};
    bool m_rate_limited{false};

    QLabel* m_status_label{nullptr};
    QLabel* m_findings_label{nullptr};
    QLabel* m_plan_label{nullptr};
    QLabel* m_warning_label{nullptr};
    QLabel* m_error_label{nullptr};
    QCheckBox* m_override_checkbox{nullptr};
    QLineEdit* m_confirm_edit{nullptr};
    QPushButton* m_repair_button{nullptr};
};

#endif // BITCOIN_QT_REPAIRDIALOG_H
