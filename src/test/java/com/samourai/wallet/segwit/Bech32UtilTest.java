package com.samourai.wallet.segwit;


import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

import static org.junit.Assert.*;

public class Bech32UtilTest {
    // test vectors
    private static String[] VALID_CHECKSUM = {
            "A12UEL5L",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w"
    };

    private static String[][] VALID_ADDRESS = {
            // example provided in BIP
            new String[] { "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"},
            // test vectors
            new String[] { "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"},
            new String[] { "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7","00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"},
            new String[] { "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx", "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"},
            new String[] { "BC1SW50QA3JX3S", "6002751e"},
            new String[] { "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", "5210751e76e8199196d454941c45d1b3a323"},
            new String[] { "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"},
            // https://blockchain.info/tx/c23248b87ae5f1533e62d4e5f99ac4373a209a38050ac78b1c84b8b7b8d91b1f
            new String[] { "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej", "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"},
    };

    // test vectors
    private static String[] INVALID_ADDRESS = {
            //"tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",                     // bad checksum
            "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
            "bc1rw5uspcuh",
            "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7", // mixed case
            "tb1pw508d6qejxtdg4y5r3zarqfsj6c3",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
    };

    private Bech32Util bech32Util = Bech32Util.getInstance();
    private SegwitAddressUtil segwitAddressUtil = SegwitAddressUtil.getInstance();

    @Test
    public void bech32DecodeValidChecksum() throws Exception {
        for(String s : VALID_CHECKSUM)   {
            bech32Util.bech32Decode(s);
        }
    }

    @Test
    public void bech32DecodeValidAddresses() throws Exception {
        for(String[] s : VALID_ADDRESS)   {
            verifyAddress(s[1], s[0]);
        }
    }

    @Test
    public void bech32DecodeInvalidAddresses() throws Exception {
        for(String s : INVALID_ADDRESS)   {
            try {
                verifyAddress(null, s);
                fail(s + " should not be a valid address");
            } catch(Exception ignore) {
            }
        }
    }

    private void verifyAddress(String expectedDecoded, String encodedAddress) throws Exception {
        byte witVer;
        String hrp = new String(bech32Util.bech32Decode(encodedAddress).getLeft());

        byte[] witProg;
        Pair<Byte, byte[]> _p;
        try {
            _p = segwitAddressUtil.decode(hrp, encodedAddress);
            witVer = _p.getLeft();
            witProg = _p.getRight();
        }
        catch(Exception e) {
            e.printStackTrace();
            hrp = "tc";
            _p = segwitAddressUtil.decode(hrp, encodedAddress);
            witVer = _p.getLeft();
            witProg = _p.getRight();
        }

        byte[] scriptPubkey = segwitAddressUtil.getScriptPubkey(witVer, witProg);
        System.out.println("witprog:" + Hex.toHexString(witProg));
        Pair<byte[], byte[]> __p = bech32Util.bech32Decode(encodedAddress);
        assertEquals(hrp, new String(__p.getLeft()));
        System.out.println("encodedAddress:         :" + encodedAddress);
        byte[] h = __p.getLeft();
        byte[] b = __p.getRight();
        System.out.println("bech32 decoded:      " + Hex.toHexString(b));
        String encoded = Bech32Util.getInstance().bech32Encode(h, b);
        System.out.println("bech32 encoded:" + encoded);
        String addr = segwitAddressUtil.encode(h, witVer, witProg);
        if( expectedDecoded != null) {
            assertEquals(expectedDecoded, Hex.toHexString(scriptPubkey));
        }
        assertEquals(encodedAddress.toLowerCase(), addr.toLowerCase());
    }
}
