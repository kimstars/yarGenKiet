/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule SmadavLog {
   meta:
      description = "MP - file SmadavLog.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "4f54a6555a7a3bec84e8193d2ff9ae75eb7f06110505e78337fa2f515790a562"
   strings:
      $s1 = "e:\\Documents and Settings\\Smadav\\My Documents\\Visual Studio 2008\\Projects\\SmadHookDev14\\Release\\SmadHookDev.pdb" fullword ascii
      $s2 = "SmadHook32c.dll" fullword ascii
      $s3 = "SmadHookDev.exe" fullword ascii
      $s4 = "SmadHook.exe" fullword wide
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s6 = "/http://crl4.digicert.com/sha2-assured-cs-g1.crl0L" fullword ascii
      $s7 = " constructor or from DllMain." fullword ascii
      $s8 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s9 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDP" fullword ascii
      $s10 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPAD" ascii
      $s11 = "Palangkaraya1" fullword ascii
      $s12 = "SmadHook32" fullword wide
      $s13 = "Zainuddin Nafarin1" fullword ascii
      $s14 = "gMMMMP\\^`^^" fullword ascii
      $s15 = "  </trustInfo>" fullword ascii
      $s16 = "StartProtect" fullword ascii
      $s17 = "Zainuddin Nafarin0" fullword ascii
      $s18 = "Smadav Software" fullword wide
      $s19 = "Smadav Whitelisting Protection" fullword wide
      $s20 = "SmadHook" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule SmadHook32c {
   meta:
      description = "MP - file SmadHook32c.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "e503fd461599b1c07dee16a026ebf24ae6d07401c3942ed32ec262db3f047ef4"
   strings:
      $s1 = "XKKtCjmrbPo.dll" fullword ascii
      $s2 = "xtmacswguyhkchetsdllkbmgunisfai" fullword ascii
      $s3 = " Type Descriptor'" fullword ascii
      $s4 = "dawhlxwphugbbfjjjo" fullword ascii
      $s5 = "sabiadypwnlpw" fullword ascii
      $s6 = "bllchkvfhhrlqtdbikoonduqqrjbuvfsqi" fullword ascii
      $s7 = "fcgnodhvpgafkgnrvqgbegcft" fullword ascii
      $s8 = "ukfysoauknlk" fullword ascii
      $s9 = "wlsakvsdmkpmwacmkihyyab" fullword ascii
      $s10 = "mvaxxawfgvferfruplcfnbtjdiavkbxhscwstuaunsr" fullword ascii
      $s11 = "gbrpleujmoncoaskirxheexasimccrwxdml" fullword ascii
      $s12 = " Class Hierarchy Descriptor'" fullword ascii
      $s13 = " Base Class Descriptor at (" fullword ascii
      $s14 = " Complete Object Locator'" fullword ascii
      $s15 = "StartProtect" fullword ascii
      $s16 = "<'<E<L<P<T<X<\\<`<d<h<" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "9i9o9{9" fullword ascii /* Goodware String - occured 1 times */
      $s18 = ">!>&>,>4>9>?>G>L>R>Z>_>e>m>r>x>" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "8 8(80848<8P8X8l8" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "1%1,1x1" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule SmadavLogofs_SmadDB {
   meta:
      description = "MP - file SmadDB.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "4b63ecd7a4486b3bf6f99160ae7ddde2c4d6043876d731e22637e0b1c08fb173"
   strings:
      $s1 = "bVwJ$i6" fullword ascii
      $s2 = "tBvN'ssZ" fullword ascii
      $s3 = "x.AVOd8}4" fullword ascii
      $s4 = "tBvN'6l" fullword ascii
      $s5 = "EmjBv??" fullword ascii
      $s6 = "cTBinP" fullword ascii
      $s7 = "tBvN'hq" fullword ascii
      $s8 = "ZOELDS" fullword ascii
      $s9 = "w=+ms%s:MMB" fullword ascii
      $s10 = "AJSYh9" fullword ascii
      $s11 = "\\*y?+Z" fullword ascii
      $s12 = "\\*q&S\"<" fullword ascii
      $s13 = "\\~`.uN" fullword ascii
      $s14 = "^`)'8n" fullword ascii
      $s15 = "Wm{1be2" fullword ascii
      $s16 = "xF9B)I " fullword ascii
      $s17 = "4uiH/#" fullword ascii
      $s18 = "L`)'8n" fullword ascii
      $s19 = "zq+CBE" fullword ascii
      $s20 = "({+%|W" fullword ascii
   condition:
      uint16(0) == 0x00c1 and filesize < 700KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

