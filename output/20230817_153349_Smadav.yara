/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule SmadavProtect {
   meta:
      description = "MP - file SmadavProtect.exe"
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
      hash1 = "8a899f7ab6b0b63fd6156acce81619ea3ff18299389484d7e5715e65f04f7316"
   strings:
      $s1 = "iNYknQlFXcZ.dll" fullword ascii
      $s2 = " Type Descriptor'" fullword ascii
      $s3 = "psyurlvuepqpyxmousepaoxeae" fullword ascii
      $s4 = "bqsqnsdwhbshrpbcejklfsydiumsxosnrwbwwqmjpx" fullword ascii
      $s5 = "pjoklwopvgyxuixkouhsstturmjsittiuveakjt" fullword ascii
      $s6 = "gxikyppphxflysqawsyergcnhbtdcpsia" fullword ascii
      $s7 = "wyukbytqfocpgynvph" fullword ascii
      $s8 = " Class Hierarchy Descriptor'" fullword ascii
      $s9 = " Base Class Descriptor at (" fullword ascii
      $s10 = " Complete Object Locator'" fullword ascii
      $s11 = "StartProtect" fullword ascii
      $s12 = "<K=P=Y=e=j=" fullword ascii /* Goodware String - occured 1 times */
      $s13 = ">!>+>5>E>U>e>n>" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "7 7(7-737;7@7F7N7S7Y7a7f7l7t7y7" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "5C5P5g5" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "4 4X4\\4" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "8C9M9h9" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "808<8X8x8" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "B0q0z0" fullword ascii /* Goodware String - occured 1 times */
      $s20 = ";b<g<l<" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule Smadav_SmadDB {
   meta:
      description = "MP - file SmadDB.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "1c7897a902b35570a9620c64a2926cd5d594d4ff5a033e28a400981d14516600"
   strings:
      $s1 = "5xCYsqlRnwxFcCFxalrEZoxCYsqlRnwxFcCFxalrEZoxCYsqlRnwxFcCFxalrEZoxCYsqlRnwxFcCFxalrEZoxCYsqlRnwxFcCFxalrEZoxCYsqlRnwxFcCFxalrEZox" ascii
      $s2 = "sqlRnxgF$x:\\qc" fullword ascii
      $s3 = "DcC.pclr/Z8" fullword ascii
      $s4 = "vEVoxCmDKVR" fullword ascii
      $s5 = "Rntx.cCGxR" fullword ascii
      $s6 = "QS:\"Fc6" fullword ascii
      $s7 = "xFcCFw~l4~.KhL" fullword ascii
      $s8 = "x:\\]c1" fullword ascii
      $s9 = "C(xal.EZo]C=sql[nwxKcIFxa" fullword ascii
      $s10 = "QPuDR.AEZo(EY?qlRbFhwwr^I}]Rt~^PruBA]f_OIzR" fullword ascii
      $s11 = "BkWb~nT%x,N" fullword ascii
      $s12 = "\\vtV^lrEBU]~_CIzR" fullword ascii
      $s13 = "Hnfwxk0" fullword ascii
      $s14 = "\\#HsqlRnw" fullword ascii
      $s15 = "prqloh" fullword ascii
      $s16 = "~c?&- " fullword ascii
      $s17 = "\\wlrEZ?" fullword ascii
      $s18 = "\\BbCFxalrt" fullword ascii
      $s19 = "bgLFxLs0" fullword ascii
      $s20 = "\\_XsqlRnwI" fullword ascii
   condition:
      uint16(0) == 0x6178 and filesize < 1000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

