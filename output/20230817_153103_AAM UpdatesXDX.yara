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

rule AAM_UpdatesXDX_hex {
   meta:
      description = "MP - file hex.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "22f2d015e39f84d0b92c5e919cee874f83826c9541608af634aa896682558402"
   strings:
      $s1 = "dllmain.dll" fullword ascii
      $s2 = "CEFProcessForkHandlerEx" fullword ascii
      $s3 = ": :%:0:=:G:\\:h:n:" fullword ascii
      $s4 = "Rich{2}" fullword ascii
      $s5 = "2+3X5_5/666" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      all of them
}

rule adobeupdate {
   meta:
      description = "MP - file adobeupdate.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "d8882948a7fe4b16fb4b7c16427fbdcf0f0ab8ff3c4bac34f69b0a7d4718183e"
   strings:
      $s1 = "3NBaOiaDVRiNBaOiaDVRiNBaOiaDVRiNBaOiaDVRiNBaOiaDVRiNBaOiaDVRiNBaOiaDVRiNBaOiaDVRiNBaOiaDVRiNBaOiaDVRiNBaOiaDVRiNBaOiaDVRiNBaOiaD" ascii
      $s2 = "YlogPt{^v" fullword ascii
      $s3 = "OiaDV?i%BaOia%V4iNBaO" fullword ascii
      $s4 = "BLO%a%V&i BaOia0V&icB3O<aDV0i BLO a" fullword ascii
      $s5 = "X@l^SZx}uM[hlfSrx%u%[" fullword ascii
      $s6 = "U@c^\\Zw}zMThcf\\rw%z%T" fullword ascii
      $s7 = "CcNk`FWPhLCcNk`FWPhLCcNk`FWPhLCcNk`FWPhLCqOyaTVBinBAOIadVrinBAOIadVrinBAOIadVrinBAOIadVrinBAOIadVrinBAOIadVrinBAOIaLVBi^BqOyaTVB" ascii
      $s8 = "oVSBxuuu[`l~Szx]uiqFVBiNB" fullword ascii
      $s9 = "RiNBaOiaDVRiNB`OkaDVbiN" fullword ascii
      $s10 = "(TBiNBa%i" fullword ascii
      $s11 = "ZNbcOmbDVB]ZvM{]Uxb" fullword ascii
      $s12 = "CcNk`FWPhLCcNk`FWPhLCcNk`FWPhLCcNk`FWPhLCqOyaTVBinBAOIadVrinBAOIadVrinBAOIadVrinBAOIadVrinBAOIadVrinBAOIadVrinBAOIaLVBi^BqOyaTVB" ascii
      $s13 = "ZFFXUNB" fullword ascii
      $s14 = "ZFFXENB" fullword ascii
      $s15 = "\\6wiyrWd`x_" fullword ascii
      $s16 = "\\RtNy]W~`" fullword ascii
      $s17 = "\\ZtFyEW~`" fullword ascii
      $s18 = "\\Jtmy}WX`v_btUyUW" fullword ascii
      $s19 = "\\DhVWF|mqy_PhJWR|AqM_lh~W~|UqQ_xh" fullword ascii
      $s20 = "\\pUQyN7t" fullword ascii
   condition:
      uint16(0) == 0x424e and filesize < 500KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

