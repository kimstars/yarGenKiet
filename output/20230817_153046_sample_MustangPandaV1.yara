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

rule sample_MustangPandaV1_hex {
   meta:
      description = "MP - file hex.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "af6cb7f9aaa2e1cff577888164f689c4bdb62490bd78915595d7fdd6462d09c4"
   strings:
      $s1 = "dllmain.dll" fullword ascii
      $s2 = "CEFProcessForkHandlerEx" fullword ascii
      $s3 = "Rich{2}" fullword ascii
      $s4 = " 1'1|1" fullword ascii
      $s5 = "9!9&9+969C9M9b9n9t9" fullword ascii
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
      hash1 = "635508330cf1a8359737f46f9c382694783a84640beb88e3dcf1c537874e77b7"
   strings:
      $s1 = "uqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJ" ascii
      $s2 = "6qJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqV" ascii
      $s3 = "6qJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqV" ascii
      $s4 = "eAiJqJti4sF.yaq" fullword ascii
      $s5 = "t:\"{q\"" fullword ascii
      $s6 = "aqptQu9" fullword ascii
      $s7 = "%INu%f" fullword ascii
      $s8 = "q%t%uQV&y" fullword ascii
      $s9 = "yaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJtQuqVCyaqJt0" fullword ascii
      $s10 = "aqJtQu0" fullword ascii
      $s11 = "\\uqVC >." fullword ascii
      $s12 = "JtQu486" fullword ascii
      $s13 = "q%t%uQV/y" fullword ascii
      $s14 = "JtSw6375" fullword ascii
      $s15 = "q9tQuTV4y" fullword ascii
      $s16 = "drFByaq" fullword ascii
      $s17 = "LsFYiaq" fullword ascii
      $s18 = "yaqJDYEaf[IAAbDaEIf" fullword ascii
      $s19 = "q$tQuqV0y" fullword ascii
      $s20 = "QurV+yapJG" fullword ascii
   condition:
      uint16(0) == 0x744a and filesize < 500KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

