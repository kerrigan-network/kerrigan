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
    // Guard against wallet unload during Groth16 proof generation (#661)
    if (!m_model) {
        Q_EMIT error(tr("Wallet was closed during transaction creation"));
        return;
    }
    try {
        QString txid = m_model->saplingZSendMany(m_from, m_recipients, m_minconf);
        Q_EMIT finished(txid);
    } catch (const std::exception& e) {
        Q_EMIT error(QString::fromStdString(e.what()));
    }
}
