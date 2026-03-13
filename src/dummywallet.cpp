// Copyright (c) 2018-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <logging.h>
#include <util/system.h>
#include <walletinitinterface.h>

class ArgsManager;
namespace interfaces {
class Chain;
class Handler;
class Wallet;
class WalletClient;
class WalletLoader;
} // namespace interfaces
namespace node {
struct NodeContext;
} // namespace node
namespace wallet {
class CWallet;
} // namespace wallet

class DummyWalletInit : public WalletInitInterface {
public:

    bool HasWalletSupport() const override {return false;}
    void AddWalletOptions(ArgsManager& argsman) const override;
    bool ParameterInteraction() const override {return true;}
    void Construct(node::NodeContext& node) const override {LogPrintf("No wallet support compiled in!\n");}

    // Kerrigan Specific WalletInitInterface
    void AutoLockMasternodeCollaterals(interfaces::WalletLoader& wallet_loader) const override {}
    void InitAutoBackup() const override {}
};

void DummyWalletInit::AddWalletOptions(ArgsManager& argsman) const
{
    argsman.AddHiddenArgs({
        "-avoidpartialspends",
        "-consolidatefeerate=<amt>",
        "-createwalletbackups=<n>",
        "-disablewallet",
        "-instantsendnotify=<cmd>",
        "-keypool=<n>",
        "-maxapsfee=<n>",
        "-maxtxfee=<amt>",
        "-rescan=<mode>",
        "-salvagewallet",
        "-signer=<cmd>",
        "-spendzeroconfchange",
        "-wallet=<path>",
        "-walletbackupsdir=<dir>",
        "-walletbroadcast",
        "-walletdir=<dir>",
        "-walletnotify=<cmd>",
        "-discardfee=<amt>",
        "-fallbackfee=<amt>",
        "-mintxfee=<amt>",
        "-paytxfee=<amt>",
        "-txconfirmtarget=<n>",
        "-hdseed=<hex>",
        "-mnemonic=<text>",
        "-mnemonicpassphrase=<text>",
        "-usehd",
        "-dblogsize=<n>",
        "-flushwallet",
        "-privdb",
        "-walletrejectlongchains",
        "-walletcrosschain",
        "-unsafesqlitesync",
    });
}

const WalletInitInterface& g_wallet_init_interface = DummyWalletInit();

namespace interfaces {

std::unique_ptr<Wallet> MakeWallet(const std::shared_ptr<wallet::CWallet>& wallet)
{
    throw std::logic_error("Wallet function called in non-wallet build.");
}

std::unique_ptr<WalletClient> MakeWalletLoader(Chain& chain, ArgsManager& args, node::NodeContext& node_context)
{
    throw std::logic_error("Wallet function called in non-wallet build.");
}

} // namespace interfaces
