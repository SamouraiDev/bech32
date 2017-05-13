package com.samourai.wallet.segwit;

import org.spongycastle.util.encoders.Hex;

import org.apache.commons.lang3.tuple.Pair;

// https://github.com/sipa/bech32/blob/master/bip-witaddr.mediawiki

public class Main {

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
            new String[] { "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx", "8128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"},
            new String[] { "BC1SW50QA3JX3S", "9002751e"},
            new String[] { "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", "8210751e76e8199196d454941c45d1b3a323"},
            new String[] { "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"},
    };

    // test vectors
    private static String[] INVALID_ADDRESS = {
            "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
//            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",                     // bad checksum
            "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
            "bc1rw5uspcuh",
            "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
//            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7", // mixed case
            "tb1pw508d6qejxtdg4y5r3zarqfsj6c3",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
    };

    public static void main(String[] args) {

        try {

            Pair<byte[], byte[]> p = null;

            for(String s : VALID_CHECKSUM)   {
                System.out.println("decoding:" + s);
                p = Bech32Util.getInstance().bech32Decode(s);
                byte[] b = p.getRight();
//                System.out.println("hex:" + Hex.toHexString(b));
            }

            for(String[] s : VALID_ADDRESS)   {
                System.out.println("decoding:" + s[0]);
                p = Bech32Util.getInstance().bech32Decode(s[0]);
                byte[] b = p.getRight();
//                System.out.println("hex:" + Hex.toHexString(b));
            }

            for(String s : INVALID_ADDRESS)   {
                System.out.println("decoding:" + s);
                p = Bech32Util.getInstance().bech32Decode(s);
                byte[] b = p.getRight();
//                System.out.println("hex:" + Hex.toHexString(b));
            }

            System.out.println("");

            for(String[] s : VALID_ADDRESS)   {

                byte witVer;
                String hrp = new String((byte[])Bech32Util.getInstance().bech32Decode(s[0]).getLeft());

                byte[] witProg;
                Pair<Byte, byte[]> _p = null;
                try {
                    _p = SegwitAddressUtil.getInstance().decode(hrp, s[0]);
                    witVer = _p.getLeft();
                    witProg = _p.getRight();
                }
                catch(Exception e) {
                    e.printStackTrace();
                    hrp = "tc";
                    _p = SegwitAddressUtil.getInstance().decode(hrp, s[0]);
                    witVer = _p.getLeft();
                    witProg = _p.getRight();
                }

                byte[] scriptPubkey = SegwitAddressUtil.getInstance().getScriptPubkey(witVer, witProg);
//                System.out.println(" in:" + s[1]);
//                System.out.println("out:" + Hex.toHexString(scriptPubkey));
//                System.out.println("witprog:" + Hex.toHexString(witProg));
                if(!Hex.toHexString(scriptPubkey).equals(s[1]))    {
                    throw new Exception();
                }
                Pair<byte[], byte[]> __p = Bech32Util.getInstance().bech32Decode(s[0]);
                if(!hrp.equals(new String(__p.getLeft())))    {
                    throw new Exception();
                }
//                System.out.println("s[0]:         :" + s[0]);
                byte[] h = __p.getLeft();
                byte[] b = __p.getRight();
//                System.out.println("bech32 decoded:      " + Hex.toHexString(b));
//                String encoded = Bech32Util.getInstance().bech32Encode(h, b);
//                System.out.println("bech32 encoded:" + encoded);
                String addr = SegwitAddressUtil.getInstance().encode(h, witVer, witProg);
                System.out.println("decoded:" + s[0]);
                System.out.println("encoded:" + addr);
                if(!s[0].equalsIgnoreCase(addr))  {
                    throw new Exception();
                }
                System.out.println("");
            }

        }
        catch(Exception e) {
            e.printStackTrace();
        }

    }

}
