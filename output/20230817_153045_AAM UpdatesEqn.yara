/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule AAM_Updates {
   meta:
      description = "MP - file AAM Updates.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "0459e62c5444896d5be404c559c834ba455fa5cae1689c70fc8c61bc15468681"
   strings:
      $x1 = "C:\\builds\\ACC\\GM\\source\\dev\\target\\win32\\Release\\HEX\\Adobe CEF Helper.pdb" fullword ascii
      $s2 = "HEX.dll" fullword wide
      $s3 = "Adobe CEF Helper.exe" fullword wide
      $s4 = "CEFProcessForkHandlerEx" fullword ascii
      $s5 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s6 = "http://sw1.symcb.com/sw.crt0" fullword ascii
      $s7 = "http://sw.symcb.com/sw.crl0" fullword ascii
      $s8 = " Type Descriptor'" fullword ascii
      $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s10 = "Adobe Systems Incorporated1" fullword ascii
      $s11 = "Adobe Systems Incorporated0" fullword ascii
      $s12 = "Aapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
      $s13 = "nFailed to remove file spec error: %d" fullword wide
      $s14 = "Copyright 2013-2016 Adobe Systems Incorporated. All rights reserved." fullword wide
      $s15 = "b<log10" fullword ascii
      $s16 = " Base Class Descriptor at (" fullword ascii
      $s17 = " Class Hierarchy Descriptor'" fullword ascii
      $s18 = " Complete Object Locator'" fullword ascii
      $s19 = "Aadvapi32" fullword wide
      $s20 = "owner dead" fullword ascii /* Goodware String - occured 567 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule AAM_UpdatesEqn_hex {
   meta:
      description = "MP - file hex.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "7456ddf511e1717af17fd8224bba94153391e3bcda6540127cf7f79b75906d2a"
   strings:
      $s1 = "hex.dll" fullword ascii
      $s2 = "CEFProcessForkHandlerEx" fullword ascii
      $s3 = "xvapqybkbmnmodbqsuibpjthydclugfmpgqxna" fullword ascii
      $s4 = "hbphxbgvqwxljwnhykfqhhtkptqjvkgvadiavudf" fullword ascii
      $s5 = "medvbuyjujapn" fullword ascii
      $s6 = "4!4h4{4" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "<,=B=u=" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "<*<7<A<K<S<a<" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "020F0Z0" fullword ascii /* Goodware String - occured 1 times */
      $s10 = ">H>M>i>|>" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "^}%95|" fullword ascii /* Goodware String - occured 2 times */
      $s12 = "7-84888<8@8D8H8L8P8" fullword ascii /* Goodware String - occured 3 times */
      $s13 = "2 4L4X4t4" fullword ascii
      $s14 = "7?8E8P8V8r8x8" fullword ascii
      $s15 = "7@8[8j8" fullword ascii
      $s16 = "30i0w0" fullword ascii
      $s17 = "1B1W1d1" fullword ascii
      $s18 = "=0=E=c=q=~=" fullword ascii
      $s19 = "2_3L5W5_5r5x5" fullword ascii
      $s20 = "8]9c9x9" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule adobeupdate {
   meta:
      description = "MP - file adobeupdate.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "e3fafa3b5c5eb9edd1002a848312bc182460f2ff9c0df732e6b6acf6e00fc5ea"
   strings:
      $s1 = "cY8QNPJRuFcYzQNPJRuFcYzQNPJRuFcYzQNPJRuFcYzQNPJRuFcYzQNPJRuFcYzQNPJRuFcYzQNPJRuFcYzQNPJRuFcYzQNPJRuFcYzQNPJRuFcYzQNPJRuFcYzQNPJR" ascii
      $s2 = "-7>*%&7='" fullword ascii /* hex encoded string 'w' */
      $s3 = "u%cczQNPJwu%ccz" fullword ascii
      $s4 = "yRZS}Fc]BS^TBRuNw[jVFPJBMDsPrQNLrPeLkYzyvRZ^}FcmBS^@BRu" fullword ascii
      $s5 = "uFcmDS^" fullword ascii
      $s6 = "JRuN![j" fullword ascii
      $s7 = "PJRu.cYzA" fullword ascii
      $s8 = "knu.Ruc" fullword ascii
      $s9 = "OS^yNRuNU[j{JPJFCDsr~QNp|PejgYz}xRZ" fullword ascii
      $s10 = "|RZAuFcYIS^DJRuNP[jDNPJBFDsOzQNHyPe^cYzq}RZKuFcqIS^JJRuvP[jJNPJjFDsEzQN" fullword ascii
      $s11 = "JRun^[j" fullword ascii
      $s12 = "u2c.zQN*J'ukc#z0NPJ" fullword ascii
      $s13 = "JRuNP[jBNPJ" fullword ascii
      $s14 = "JRuN#[j" fullword ascii
      $s15 = "JRunW[jiNPJ" fullword ascii
      $s16 = "ufc7z>N$Jru#c7z>N%J5u.cyz\"N J3u%c<zqN6J=u4cyz=N?J%u/c6zqN9J<u/c-z8N1J>u/c#z0N$J;u)c7z\\NZJRuFcYzQN" fullword ascii
      $s17 = "9S^0JRuNW[jeNPJ" fullword ascii
      $s18 = "N}J1u)c4z!N9J>u#c=zqNxJ}u%c5z#NyJru c,z?N3J&u/c6z?NpJ4u4c6z<NpJ3ufc7z0N$J;u0c<zqN3J=u(c*z%N\"J'u%c-z>N\"Jru)c+zqN6J u)c4zqN" fullword ascii
      $s19 = "cozaNaJjuKcSz|NpJ'u(c<z)N J7u%c-z4N4Jru.c<z0N Jru#c+z#N?J uKcSzQNPJRuFc" fullword ascii
      $s20 = "Jyumcyz" fullword ascii
   condition:
      uint16(0) == 0x7552 and filesize < 500KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

