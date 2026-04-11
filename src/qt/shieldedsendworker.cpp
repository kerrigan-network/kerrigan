// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license.

#include <qt/shieldedsendworker.h>
#include <qt/walletmodel.h>

#include <stdexcept>

ShieldedSendWorker::ShieldedSendWorker(WalletModel* model,
                                       const QString& from,
                                       const QList<QPair<QString, CAmount>>& recipients,
                                       int minconf,
                                       QObject* parent)
    : QObject(parent)
    , m_model(model)
    , m_from(from)
    , m_recipients(recipients)
    , m_minconf(minconf)
{
}

void ShieldedSendWorker::process()
{
    // Guard against wallet unload before Groth16 proof generation begins.
    // m_model is a QPointer that auto-nulls when the WalletModel is destroyed.
    if (!m_model) {
        Q_EMIT error(tr("Wallet was closed during proof generation"));
        return;
    }
    try {
        QString txid = m_model->saplingZSendMany(m_from, m_recipients, m_minconf);

        // Re-check after the (potentially long) proof generation completes.
        // If the wallet was destroyed mid-call, saplingZSendMany should throw,
        // but belt-and-suspenders: verify the model is still alive before
        // reporting success.
        if (!m_model) {
            Q_EMIT error(tr("Wallet was closed during proof generation"));
            return;
        }

        Q_EMIT finished(txid);
    } catch (const std::exception& e) {
        Q_EMIT error(QString::fromStdString(e.what()));
    }
}
