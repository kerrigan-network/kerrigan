// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/uritests.h>

#include <qt/guiutil.h>
#include <qt/walletmodel.h>

#include <key_io.h>
#include <sapling/sapling_address.h>

#include <QUrl>

void URITests::uriTests()
{
    SendCoinsRecipient rv;
    QUrl uri;
    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?req-dontexist="));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?dontexist="));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?label=Some Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
    QVERIFY(rv.label == QString("Some Example Address"));
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?amount=0.001"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100000);

    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?amount=1.001"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100100000);

    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?amount=100&label=Some Example"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("Some Example"));

    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?message=Some Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
    QVERIFY(rv.label == QString());

    QVERIFY(GUIUtil::parseBitcoinURI("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?message=Some Example Address", &rv));
    QVERIFY(rv.address == QString("XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
    QVERIFY(rv.label == QString());

    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?req-message=Some Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));

    // Commas in amounts are not allowed.
    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?amount=1,000&label=Some Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?amount=1,000.0&label=Some Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    // There are two amount specifications. The last value wins.
    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?amount=100&amount=200&label=Wikipedia Example"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
    QVERIFY(rv.amount == 20000000000LL);
    QVERIFY(rv.label == QString("Wikipedia Example"));

    // The first amount value is correct. However, the second amount value is not valid. Hence, the URI is not valid.
    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?amount=100&amount=1,000&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    // Test label containing a question mark ('?').
    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?amount=100&label=?"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("?"));

    // Escape sequences are not supported.
    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?amount=100&label=%3F"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("%3F"));

    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?amount=100&label=Some Example&message=Some Example Message"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("Some Example"));
    QVERIFY(rv.message == QString("Some Example Message"));

    // Verify that IS=xxx does not lead to an error (we ignore the field)
    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?IS=1"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?req-IS=1"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));

    // Sapling memo (ZIP 321): base64url without padding, shielded recipients only
    sapling::SaplingPaymentAddress zaddr;
    zaddr.d.fill(0x01);
    zaddr.pk_d.fill(0x02);
    const QString zaddrStr = QString::fromStdString(EncodeSaplingAddress(zaddr));

    uri.setUrl(QString("kerrigan:%1?amount=0.1&memo=MTI").arg(zaddrStr));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == zaddrStr);
    QVERIFY(rv.amount == 10000000);
    QVERIFY(rv.memo == QString("12"));

    // req-memo is understood
    uri.setUrl(QString("kerrigan:%1?req-memo=MTI").arg(zaddrStr));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.memo == QString("12"));

    // A memo is not allowed for a transparent address
    uri.setUrl(QString("kerrigan:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?memo=MTI"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    // Invalid base64url
    uri.setUrl(QString("kerrigan:%1?memo=M!I").arg(zaddrStr));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    // More than 512 bytes
    const QString tooLong = QString::fromLatin1(QByteArray(513, 'a').toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
    uri.setUrl(QString("kerrigan:%1?memo=%2").arg(zaddrStr, tooLong));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    // Not UTF-8 text
    uri.setUrl(QString("kerrigan:%1?memo=_w").arg(zaddrStr)); // 0xFF
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    // A NUL inside the text; trailing zero padding is fine
    uri.setUrl(QString("kerrigan:%1?memo=YQBi").arg(zaddrStr)); // "a\0b"
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));
    uri.setUrl(QString("kerrigan:%1?memo=YWIAAA").arg(zaddrStr)); // "ab\0\0"
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.memo == QString("ab"));

    // formatBitcoinURI round trip
    SendCoinsRecipient zrcp;
    zrcp.address = zaddrStr;
    zrcp.amount = 10000000;
    zrcp.memo = QString::fromUtf8("Order #42 \xe2\x80\x93 thanks");
    SendCoinsRecipient parsed;
    QVERIFY(GUIUtil::parseBitcoinURI(GUIUtil::formatBitcoinURI(zrcp), &parsed));
    QVERIFY(parsed.address == zrcp.address);
    QVERIFY(parsed.amount == zrcp.amount);
    QVERIFY(parsed.memo == zrcp.memo);
}
