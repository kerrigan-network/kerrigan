// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license.

#ifndef KERRIGAN_QT_SHIELDEDSENDWORKER_H
#define KERRIGAN_QT_SHIELDEDSENDWORKER_H

#include <qt/sendcoinsrecipient.h>
#include <wallet/sapling_send.h>

#include <QList>
#include <QObject>
#include <QPointer>
#include <QString>

class WalletModel;

/**
 * Worker object for performing shielded (Sapling) z_sendmany transactions
 * on a background QThread. Groth16 proof generation is CPU-intensive and
 * must not block the GUI thread.
 */
class ShieldedSendWorker : public QObject
{
    Q_OBJECT

public:
    ShieldedSendWorker(WalletModel* model,
                       const wallet::SaplingSendSource& source,
                       const QList<SendCoinsRecipient>& recipients,
                       int minconf = 1,
                       QObject* parent = nullptr);

public Q_SLOTS:
    void process();

Q_SIGNALS:
    void finished(const QString& txid);
    void error(const QString& message);

private:
    QPointer<WalletModel> m_model;
    wallet::SaplingSendSource m_source;
    QList<SendCoinsRecipient> m_recipients;
    int m_minconf;
};

#endif // KERRIGAN_QT_SHIELDEDSENDWORKER_H
