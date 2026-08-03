// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/repairdialog.h>

#include <interfaces/node.h>
#include <qt/guiutil.h>

#include <cassert>

#include <QCheckBox>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

//! The confirmation word is deliberately locale-stable (not translated):
//! it is compared verbatim and appears verbatim in the instruction text.
static const QLatin1String CONFIRM_WORD{"REPAIR"};

QString RepairDialog::scopeForAction(recovery::RecommendedAction action)
{
    return action == recovery::RecommendedAction::ACTION_GUIDED_NETWORK_REPAIR
               ? QStringLiteral("network")
               : QStringLiteral("full");
}

QString RepairDialog::modeText(recovery::DaemonMode mode)
{
    switch (mode) {
    case recovery::DaemonMode::STARTING: return tr("Starting up");
    case recovery::DaemonMode::SYNCING: return tr("Syncing with the network");
    case recovery::DaemonMode::NORMAL: return tr("Healthy");
    case recovery::DaemonMode::DEGRADED: return tr("Degraded — running, but needs attention");
    case recovery::DaemonMode::QUARANTINED: return tr("Paused for safety — a data problem was detected");
    case recovery::DaemonMode::CRIPPLED_WAIT: return tr("Startup found damaged data — repair required");
    case recovery::DaemonMode::REPAIR_ARMED: return tr("Repair armed — restart to execute");
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

QString RepairDialog::findingText(recovery::FindingCode code)
{
    switch (code) {
    case recovery::FindingCode::NET_LOCAL_LINK_DOWN: return tr("The local network link appears to be down");
    case recovery::FindingCode::NET_ISOLATED: return tr("No usable peer connections");
    case recovery::FindingCode::NET_ECLIPSE_SUSPECT: return tr("Peers are known but none work — the address book may be stale or poisoned");
    case recovery::FindingCode::TIP_STALLED_NETWORK: return tr("The chain tip has stalled (network-related)");
    case recovery::FindingCode::TIP_STALLED_NONNETWORK: return tr("The chain tip has stalled (not network-related)");
    case recovery::FindingCode::DRIFT_EVODB: return tr("The masternode database disagrees with the chain (data corruption)");
    case recovery::FindingCode::DRIFT_SAPLING: return tr("The shielded-transaction database disagrees with the chain (data corruption)");
    case recovery::FindingCode::WITNESS_STALE: return tr("Shielded note witnesses are stale");
    case recovery::FindingCode::REPAIR_RATE_LIMITED: return tr("Too many repairs recently — the disk may be failing");
    case recovery::FindingCode::CHAINSTATE_LOAD_FAILED: return tr("The block database failed to load at startup");
    case recovery::FindingCode::NODE_ABORTED: return tr("The previous run stopped abnormally");
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

QString RepairDialog::actionText(recovery::RecommendedAction action)
{
    switch (action) {
    case recovery::RecommendedAction::ACTION_NONE: return tr("No action needed");
    case recovery::RecommendedAction::ACTION_WAIT_AUTO: return tr("Wait — automatic recovery is working on it");
    case recovery::RecommendedAction::ACTION_GUIDED_NETWORK_REPAIR: return tr("Reset network data (peers) — no chain data is wiped");
    case recovery::RecommendedAction::ACTION_GUIDED_REPAIR: return tr("Repair the node (wipe damaged data and resync — wallet preserved)");
    case recovery::RecommendedAction::ACTION_DIAGNOSE_SUPPORT: return tr("Manual diagnosis needed — check debug.log or ask for support");
    case recovery::RecommendedAction::ACTION_CHECK_DISK: return tr("Check disk health and free space before repairing");
    case recovery::RecommendedAction::ACTION_MANAGE_NODE_ELSEWHERE: return tr("Manage this node from the machine or wallet that runs it");
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

QString RepairDialog::phaseText(recovery::RepairPhase phase)
{
    switch (phase) {
    case recovery::RepairPhase::NONE: return tr("Not active");
    case recovery::RepairPhase::ARMED: return tr("Armed — waiting for restart");
    case recovery::RepairPhase::SHUTTING_DOWN: return tr("Shutting down to repair");
    case recovery::RepairPhase::WIPING: return tr("Removing damaged data");
    case recovery::RepairPhase::BOOTSTRAPPING: return tr("Fetching bootstrap data");
    case recovery::RepairPhase::SYNCING: return tr("Resyncing the chain");
    case recovery::RepairPhase::REBUILDING_WITNESSES: return tr("Rebuilding shielded note witnesses");
    case recovery::RepairPhase::VERIFYING: return tr("Verifying the repaired state");
    case recovery::RepairPhase::DONE: return tr("Repair completed");
    case recovery::RepairPhase::FAILED: return tr("Repair failed — see debug.log");
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

QString RepairDialog::witnessProgressText(int64_t rebuilt, int64_t total)
{
    if (total <= 0) {
        // 0 means the wallet exposes no per-note counter: honest "unknown",
        // never "0 of 0" and never a fabricated percentage.
        return tr("finalizing… (count unavailable)");
    }
    return tr("%1 of %2 rebuilt").arg(rebuilt).arg(total);
}

RepairDialog::RepairDialog(interfaces::Node& node, Context context, const QString& scope, QWidget* parent)
    : QDialog(parent),
      m_node(node),
      m_context(context),
      m_scope(scope)
{
    setWindowTitle(m_scope == QLatin1String("network") ? tr("Reset network data") : tr("Repair node"));
    setMinimumWidth(560);

    auto* layout = new QVBoxLayout(this);

    m_status_label = new QLabel(this);
    m_status_label->setWordWrap(true);
    layout->addWidget(m_status_label);

    m_findings_label = new QLabel(this);
    m_findings_label->setWordWrap(true);
    layout->addWidget(m_findings_label);

    m_plan_label = new QLabel(this);
    m_plan_label->setWordWrap(true);
    m_plan_label->setTextFormat(Qt::RichText);
    layout->addWidget(m_plan_label);

    m_warning_label = new QLabel(this);
    m_warning_label->setWordWrap(true);
    if (m_scope == QLatin1String("network")) {
        m_warning_label->setText(tr("No chain or wallet data is touched; only saved peer addresses are reset."));
    } else {
        m_warning_label->setText(
            tr("Your wallet file is preserved and your funds are safe, but shielded balances "
               "will be temporarily unspendable while note witnesses rebuild after the chain "
               "finishes resyncing. Transparent balances are usable as soon as sync completes."));
        m_warning_label->setStyleSheet(QStringLiteral("font-weight: bold;"));
    }
    layout->addWidget(m_warning_label);

    m_override_checkbox = new QCheckBox(tr("Override the repair rate limit (recorded; repeated repairs usually mean a failing disk)"), this);
    m_override_checkbox->setVisible(false);
    layout->addWidget(m_override_checkbox);

    auto* confirm_hint = new QLabel(tr("Type %1 to enable the repair button:").arg(CONFIRM_WORD), this);
    layout->addWidget(confirm_hint);

    m_confirm_edit = new QLineEdit(this);
    m_confirm_edit->setPlaceholderText(CONFIRM_WORD);
    connect(m_confirm_edit, &QLineEdit::textChanged, this, &RepairDialog::onConfirmTextChanged);
    connect(m_override_checkbox, &QCheckBox::toggled, this,
            [this] { onConfirmTextChanged(m_confirm_edit->text()); });
    layout->addWidget(m_confirm_edit);

    m_error_label = new QLabel(this);
    m_error_label->setWordWrap(true);
    m_error_label->setStyleSheet(QStringLiteral("color: #bc3634;"));
    m_error_label->setVisible(false);
    layout->addWidget(m_error_label);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
    m_repair_button = buttons->addButton(
        m_context == Context::Startup ? tr("Repair and relaunch") : tr("Repair and restart"),
        QDialogButtonBox::AcceptRole);
    m_repair_button->setEnabled(false);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(m_repair_button, &QPushButton::clicked, this, &RepairDialog::onRepairClicked);
    layout->addWidget(buttons);

    populateStatus();
    refreshPlan();
}

void RepairDialog::populateStatus()
{
    const recovery::StatusSnapshot snap = m_node.getRecoveryStatus();
    m_status_label->setText(tr("Node state: %1").arg(modeText(snap.daemon_mode)));

    if (snap.findings.empty()) {
        m_findings_label->setVisible(false);
        return;
    }
    QStringList lines;
    for (const recovery::Finding& finding : snap.findings) {
        // Human copy from the tr() table; `debug_detail` is deliberately
        // never displayed (contract 7.1).
        QString line = QStringLiteral("• ") + findingText(finding.code);
        if (finding.since > 0) {
            line += tr(" (since %1)").arg(QDateTime::fromSecsSinceEpoch(finding.since).toString(Qt::ISODate));
        }
        lines << line;
    }
    m_findings_label->setText(lines.join(QLatin1Char('\n')));
    m_findings_label->setVisible(true);
}

void RepairDialog::refreshPlan()
{
    const recovery::RepairPlan plan = m_node.repairDryRun(m_scope.toStdString());
    m_token = plan.confirm_token;

    if (m_token.empty()) {
        m_plan_label->setText(tr("Repair is unavailable right now (the recovery module is not ready)."));
        m_repair_button->setEnabled(false);
        m_confirm_edit->setEnabled(false);
        return;
    }

    const auto join = [](const std::vector<std::string>& items) {
        if (items.empty()) return tr("(none)");
        QStringList list;
        for (const std::string& item : items) {
            list << QString::fromStdString(item);
        }
        return list.join(QStringLiteral(", "));
    };
    std::vector<std::string> wiped{plan.wipe_dirs};
    wiped.insert(wiped.end(), plan.wipe_files.begin(), plan.wipe_files.end());
    m_plan_label->setText(tr("<b>Will delete:</b> %1<br><b>Preserved:</b> %2<br><b>Size estimate:</b> %3")
                              .arg(GUIUtil::HtmlEscape(join(wiped)),
                                   GUIUtil::HtmlEscape(join(plan.preserved)),
                                   plan.bytes_total_est >= 0 ? GUIUtil::formatBytes(plan.bytes_total_est) : tr("unknown")));

    m_rate_limited = plan.rate_limited;
    m_override_checkbox->setVisible(m_rate_limited);
    if (m_rate_limited) {
        m_error_label->setText(tr("This node already ran %1 repair wipes in the last 7 days. "
                                  "Repeated repairs usually mean failing hardware — check the disk first.")
                                   .arg(plan.wipes_in_window));
        m_error_label->setVisible(true);
    }
    onConfirmTextChanged(m_confirm_edit->text());
}

void RepairDialog::onConfirmTextChanged(const QString& text)
{
    const bool confirmed = text == CONFIRM_WORD;
    const bool guard_ok = !m_rate_limited || m_override_checkbox->isChecked();
    m_repair_button->setEnabled(confirmed && guard_ok && !m_token.empty());
}

void RepairDialog::onRepairClicked()
{
    // Arm = write the repair marker ONLY. The node interface has no shutdown
    // parameter, so this path can never trigger the daemon-side
    // StartShutdown() that would break the GUI restart chain (8.2).
    const recovery::ArmResult result =
        m_node.repairArm(m_token, m_scope.toStdString(), m_override_checkbox->isChecked());

    switch (result) {
    case recovery::ArmResult::ARMED:
    case recovery::ArmResult::ALREADY_ARMED:
        m_armed = true;
        accept();
        return;
    case recovery::ArmResult::BAD_TOKEN:
        // One-time tokens expire after 5 minutes; mint a fresh plan+token and
        // ask the user to confirm again.
        m_error_label->setText(tr("The confirmation expired — the plan has been refreshed, please confirm again."));
        m_error_label->setVisible(true);
        m_confirm_edit->clear();
        refreshPlan();
        return;
    case recovery::ArmResult::ATTEMPTS_EXHAUSTED:
        m_error_label->setText(tr("Too many repair attempts in the last 6 hours. Wait before trying again, "
                                  "and check the disk if repairs keep failing."));
        m_error_label->setVisible(true);
        m_repair_button->setEnabled(false);
        return;
    case recovery::ArmResult::RATE_LIMITED:
        m_error_label->setText(tr("The repair rate limit is active. Tick the override box to proceed anyway "
                                  "(the override is recorded), or check the disk first."));
        m_error_label->setVisible(true);
        m_rate_limited = true;
        m_override_checkbox->setVisible(true);
        onConfirmTextChanged(m_confirm_edit->text());
        return;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}
