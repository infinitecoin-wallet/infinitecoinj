/*
 * Copyright 2013 Google Inc.
 * Copyright 2015 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.params;

import org.bitcoinj.core.*;
import org.bitcoinj.net.discovery.*;

import java.net.*;

import static com.google.common.base.Preconditions.*;

/**
 * Parameters for the main production network on which people trade goods and services.
 */
public class MainNetParams extends AbstractBitcoinNetParams {
    public static final int MAINNET_MAJORITY_WINDOW = 40320;  // 40320 = 2880 * 14day
    public static final int MAINNET_MAJORITY_REJECT_BLOCK_OUTDATED = 38304;  // 95% of 40320
    public static final int MAINNET_MAJORITY_ENFORCE_BLOCK_UPGRADE = 30240;  // 75% of 40320

    public MainNetParams() {
        super();
        interval = INTERVAL;
        targetTimespan = TARGET_TIMESPAN;
        maxTarget = Utils.decodeCompactBits(0x1e0ffff0L);
        dumpedPrivateKeyHeader = 230;
        addressHeader = 102;
        p2shHeader = 5;
        segwitAddressHrp = "ifc";
        port = 9321;
        packetMagic = 0xfbc0b6dbL;
        bip32HeaderP2PKHpub = 0x0488b21e; // The 4 byte header that serializes in base58 to "xpub".
        bip32HeaderP2PKHpriv = 0x0488ade4; // The 4 byte header that serializes in base58 to "xprv"
        bip32HeaderP2WPKHpub = 0x04b24746; // The 4 byte header that serializes in base58 to "zpub".
        bip32HeaderP2WPKHpriv = 0x04b2430c; // The 4 byte header that serializes in base58 to "zprv"

        majorityEnforceBlockUpgrade = MAINNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = MAINNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = MAINNET_MAJORITY_WINDOW;

        genesisBlock.setDifficultyTarget(0x1e0ffff0L);
        genesisBlock.setTime(1370324666L);
        genesisBlock.setNonce(113458625);
        id = ID_MAINNET;
        subsidyDecreaseBlockCount = 86400;
        spendableCoinbaseDepth = 100;
        String genesisHash = genesisBlock.getHashAsString();
        checkState(genesisHash.equals("b10d5e83a5b2e62d9d872096bc20cae1a276ae6aacc02a71a5832b1fc9aeff85"),
                genesisHash);

        // This contains (at a minimum) the blocks which are not BIP30 compliant. BIP30 changed how duplicate
        // transactions are handled. Duplicated transactions could occur in the case where a coinbase had the same
        // extraNonce and the same outputs but appeared at different heights, and greatly complicated re-org handling.
        // Having these here simplifies block connection logic considerably.
        checkpoints.put(9999, Sha256Hash.wrap("d2f1a2f1b8862af96c5a750f3d99680ee96e7a4aac4e27f0587b1dbaa9b9207f"));
        checkpoints.put(49999, Sha256Hash.wrap("ef2a0653071708d6a41dff2bb671bb459879f2c361a06024fca17a2566b41225"));
        checkpoints.put(99979, Sha256Hash.wrap("f376177d849c75c6344fc93c9429f59df7d5b25b067447e694e087bb765128e0"));
        checkpoints.put(139999, Sha256Hash.wrap("ff9d5edf1661d8cd6fc53ffb9f583b16981874522044a760d8c8c004c312a41e"));
        checkpoints.put(199999, Sha256Hash.wrap("ec62c7700fd83c56f2013b1b97a7dbcc2aad1f065176ea18d9c47701ced164d5"));
		checkpoints.put(228800, Sha256Hash.wrap("6a2a329c5d21d6433cf9bda5ba43d66a732898bcd0c81150f1584d095edd5cd5"));
        checkpoints.put(242388, Sha256Hash.wrap("4c2dfd22435525519e89041420f6692e709da34f48243cebe1be14d43adb1c5c"));
        checkpoints.put(265420, Sha256Hash.wrap("9ef4ce8e7dab5c2f2b9142ceb285419ef0ea62021e5f613d4a81a3fc9d53453e"));
        checkpoints.put(265497, Sha256Hash.wrap("206aed8fb5b1ed94cf696bc5b964445380dd4c30c186e45ba5ed545866a242c7"));
        checkpoints.put(268559, Sha256Hash.wrap("fd0ff0e0020f0ade68122c0fd82f648c7e6913e32cd6a3d8abc81694055daecc"));
		checkpoints.put(268560, Sha256Hash.wrap("08c5337322ea40d3602b98ab9d9b1d43abd87dda19a4f8e282414a838ae3dbb8"));
        checkpoints.put(282045, Sha256Hash.wrap("271abe1c26daf5a684034529befb217e16f87e1af779c0e63bdd971def3d8ba5"));
        checkpoints.put(380962, Sha256Hash.wrap("a032a87b430091fbb4faa20f16c8247f93cfcc1854bd49a19c3c9fc3a0c43634"));
        checkpoints.put(453211, Sha256Hash.wrap("ea08eace1b78c5513d74750c7cfc01d0c1f3789fc650ccce197b85497405ce56"));
        checkpoints.put(647000, Sha256Hash.wrap("667fc19d6066d472176136f2a34dac9b2662e9d7212df3679e56042d8b198906"));
		checkpoints.put(4333333, Sha256Hash.wrap("8e4fcf3e003293882dec8943e42ed29e066cfc3782ff4d011c58c8b8ed9bb9a4"));
        checkpoints.put(4368037, Sha256Hash.wrap("b60d656dcc3fdd60b279a7de7ad8c21950c4cbae58698219785249e0174d4bcd"));
        checkpoints.put(5781980, Sha256Hash.wrap("a91e780de0b3f91f1b0515e56296b54804730cdfd21a45b4d2c433a3f92aebb7"));
        checkpoints.put(6043693, Sha256Hash.wrap("5518c133fead075e372027e69c2b245a01d5a6e95ef3c97d576bf42a62d1e6ef"));
        checkpoints.put(6887217, Sha256Hash.wrap("58edc430d6ecc35ae3fa4d8ccdfb8a42752ff771d2a08c8e6dc1f1b3b6782d4d"));
		checkpoints.put(7081698, Sha256Hash.wrap("4342f79249ffe1c4afe08fca143ee9945579528a9047afc0e79ef276ea6fde6b"));
        checkpoints.put(7900916, Sha256Hash.wrap("185d45e33bb5c8546b0923bd9c31c64c1b11eba2ae51afe549ce3e5aba63f70e"));
        checkpoints.put(8578526, Sha256Hash.wrap("a5d4766c2e9ba13efd942f2bfcb1849ce824b54130c9de3c15e80afec0f81aa5"));

        dnsSeeds = new String[] {
                "dnsseed.infinitecoin.com",
                "dnsseed.ifcf2pool.com",
                "dnsseed.amxpool.com",
                "dnsseed.coinwk.com",
                /*"seed.bitcoin.jonasschnelli.ch",// Jonas Schnelli
                "seed.btc.petertodd.org",       // Peter Todd
                "seed.bitcoin.sprovoost.nl",    // Sjors Provoost
                "dnsseed.emzy.de",*/            // Stephan Oeste
        };
        httpSeeds = null; /*new HttpDiscovery.Details[] {
                // Andreas Schildbach
                new HttpDiscovery.Details(
                        ECKey.fromPublicOnly(Utils.HEX.decode("0238746c59d46d5408bf8b1d0af5740fe1a6e1703fcb56b2953f0b965c740d256f")),
                        URI.create("http://httpseed.bitcoin.schildbach.de/peers")
                )
        };*/

        // These are in big-endian format, which is what the SeedPeers code expects.
        // Updated Apr. 11th 2019
        addrSeeds = null; /*new int[] {
                // seed.bitcoin.sipa.be
                0x117c7e18, 0x12641955, 0x1870652e, 0x1dfec3b9, 0x4a330834, 0x5b53382d, 0x77abaca3, 0x09e3d36c,
                0xa0a4e1d4, 0xa275d9c7, 0xa280bc4b, 0xa50d1b76, 0x0a5f84cb, 0xa86cd5bd, 0xb3f427ba, 0xc6fc4cd0,
                0xc73c19b9, 0xd905d85f, 0xd919f9ad, 0xda3fc312, 0xdc4ca5b9, 0xe38ef05b, 0xedce8e57, 0xf68ad23e,
                0xfb3b9c59,
                // dnsseed.bluematt.me
                0x1061d85f, 0x2d5325b0, 0x3505ef91, 0x4c42b14c, 0x623cce72, 0x067e4428, 0x6b47e32e, 0x6e47e32e,
                0x87aed35f, 0x96fe3234, 0xac81419f, 0xb6f9bb25, 0xc9ddb4b9, 0xcbd8aca3, 0xd55c09b0, 0xd5640618,
                0xdaa9144e, 0xdfb99088, 0xe0339650, 0xeb8221af, 0xfcbfd75b,
                // dnsseed.bitcoin.dashjr.org
                0x028ea62e, 0x2cf968be, 0x2d9cf023, 0x3bedb812, 0x40373745, 0x40aa9850, 0x42504a28, 0x50b8f655,
                0x5a86e548, 0x6d79f459, 0x70681b41, 0x74a8cf1f, 0x779233d4, 0x8b2380b2, 0x9dcc342f, 0xa331b5ad,
                0xa95b4c90, 0xb05ff750, 0x0bfde3d4, 0x0c15c136, 0xd3912552, 0xd56ce69d, 0xd8af5454, 0xfce48068,
                // seed.bitcoinstats.com
                0x10c23a35, 0x1168b223, 0x11ae871f, 0x14ddce34, 0x018ce3d5, 0x1b242934, 0x20bcf754, 0x33954d33,
                0x355609b0, 0x39fd202f, 0x4df35e2f, 0x4f23f22b, 0x5707f862, 0x8602bdce, 0x8e09703e, 0x90009ede,
                0x9ffb125b, 0xa33c4c90, 0xa9c4ec57, 0xaa2d5097, 0xae52fb94, 0x00ed2636, 0xedf5649f, 0x0f41a6bc,
                0xfe03cf22,
                // seed.bitcoin.jonasschnelli.ch
                0x23159dd8, 0x368fea55, 0x50bd4031, 0x5395de6c, 0x05c6902f, 0x60c09350, 0x66d6d168, 0x70d90337,
                0x7a549ac3, 0x9012d552, 0x94a60f33, 0xa490ff36, 0xb030d552, 0xb0729450, 0xb12b4c4a, 0x0b7e7e60,
                0xc4f84b2f, 0xc533f42f, 0xc8f60ec2, 0xc9d1bab9, 0xd329cb74, 0xe4b26ab4, 0xe70e5db0, 0xec072034,
                // seed.btc.petertodd.org
                0x10ac1242, 0x131c4a79, 0x1477da47, 0x2899ec63, 0x45660451, 0x4b1b0050, 0x6931d0c2, 0x070ed85f,
                0x806a9950, 0x80b0d522, 0x810d2bc1, 0x829d3b8b, 0x848bdfb0, 0x87a5e52e, 0x9664bb25, 0xa021a6df,
                0x0a5f8548, 0x0a66c752, 0xaaf5b64f, 0xabba464a, 0xc5df4165, 0xe8c5efd5, 0xfa08d01f,
                // seed.bitcoin.sprovoost.nl
                0x14420418, 0x1efdd990, 0x32ded23a, 0x364e1e54, 0x3981d262, 0x39ae6ed3, 0x5143a699, 0x68f861cb,
                0x6f229e23, 0x6fe45d8e, 0x77db09b0, 0x7a1cd85f, 0x8dd03b8b, 0x92aec9c3, 0xa2debb23, 0xa47dee50,
                0xb3566bb4, 0xcb1845b9, 0xcd51c253, 0xd541574d, 0xe0cba936, 0xfb2c26d0,
                // dnsseed.emzy.de
                0x16e0d7b9, 0x1719c2b9, 0x1edfd04a, 0x287eff2d, 0x28f54e3e, 0x3574c1bc, 0x36f1b4cf, 0x3932571b,
                0x3d6f9bbc, 0x4458aa3a, 0x4dd2cf52, 0x05483e97, 0x559caed5, 0x59496251, 0x66d432c6, 0x7501f7c7,
                0x7775599f, 0x8e0ea28b, 0x8f3d0d9d, 0x902695de, 0xa6ada27b, 0xbb00875b, 0xbc26c979, 0xd1a2c58a,
                0xf6d33b8b, 0xf9d95947,
        };*/
    }

    private static MainNetParams instance;
    public static synchronized MainNetParams get() {
        if (instance == null) {
            instance = new MainNetParams();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return PAYMENT_PROTOCOL_ID_MAINNET;
    }
}
