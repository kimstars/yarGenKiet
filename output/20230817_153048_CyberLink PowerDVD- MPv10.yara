/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule BoomerangLib {
   meta:
      description = "MP - file BoomerangLib.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "35488b3310a9ae1401f8efb2d2eaaaa1963d85681b1a8b7459bafe66415c8731"
   strings:
      $s1 = "hEFFHtG.dll" fullword ascii
      $s2 = "%temp%\\tmp276280527.tmp" fullword ascii
      $s3 = "agtiydlluoagpusljlvikbeewubqwdumwsrbtblwkp" fullword ascii
      $s4 = "\\lib.dat" fullword ascii
      $s5 = "fkmaagopaeavgdmepdpcvrkwlntukox" fullword ascii
      $s6 = "diwxgrvupseybrxr" fullword ascii
      $s7 = "tpiafvwkodjsmovfryweeme" fullword ascii
      $s8 = "towemdnqphjhffcsqnaaxdolisflkhagjrlpgsypccljcmvkt" fullword ascii
      $s9 = "kcnidbtijikxaorwjqxqivubyrvtvmprewknxkfim" fullword ascii
      $s10 = "uqmairensiviebuwefpajjloiba" fullword ascii
      $s11 = "lnjhncwsrjjes" fullword ascii
      $s12 = "tneeukvpsskxfmfxkdmtuevphixbqelvbaolvy" fullword ascii
      $s13 = "doenfolrrmvtctxbh" fullword ascii
      $s14 = "cxfkdehvie" fullword ascii
      $s15 = "xykfouiuwdfvexccgecgtpksbbnlhbub" fullword ascii
      $s16 = "ssfcvpdivijjalpafdbmoestgsvbfcewnjprg" fullword ascii
      $s17 = "hewsxqb" fullword ascii
      $s18 = "gyvlsfbqpxhuup" fullword ascii
      $s19 = "gnokviegfvsdbwbceaceilnwyoxolx" fullword ascii
      $s20 = "qfdddcilekjbyxnqvknqkopwnxj" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule PDVDPolicy {
   meta:
      description = "MP - file PDVDPolicy.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "aab8f4cef0dad38484de269b3329f63366cbbae973cd36846dbfb15b36c0bb6a"
   strings:
      $s1 = "ehexthost.exe" fullword wide
      $s2 = "@ehexthost32.exe" fullword wide
      $s3 = "BoomerangLib.dll" fullword wide
      $s4 = "PowerDVD12.exe" fullword wide
      $s5 = "PowerDVDCinema12.exe" fullword wide
      $s6 = "PDVDLaunchPolicy.exe" fullword wide
      $s7 = "e:\\SVN\\PDVD12\\HP_CMIT\\PDVDLaunchPolicy.pdb" fullword ascii
      $s8 = "UI_RES.DLL" fullword wide
      $s9 = "Movie\\PowerDVD Cinema\\PowerDVDCinema12.exe" fullword wide
      $s10 = "Movie\\PowerDVD.exe" fullword wide
      $s11 = "http://www.cyberlink.com0" fullword ascii
      $s12 = "PowerDVD12.exe.pr" fullword wide
      $s13 = "        <requestedExecutionLevel" fullword ascii
      $s14 = "\"%s\" %s -movpid=%d" fullword wide
      $s15 = " Type Descriptor'" fullword ascii
      $s16 = "<description>PDVDLaunchPolicy</description>  " fullword ascii
      $s17 = "      processorArchitecture=\"*\" />                                " fullword ascii
      $s18 = "m_hKeyLMRead" fullword wide
      $s19 = "m_hKeyCURead" fullword wide
      $s20 = "m_hKeyRead" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule CyberLink_PowerDVD__MPv10_lib {
   meta:
      description = "MP - file lib.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "2ef5e207769bf928baf369f788592095e292175e4e5f37e22abbdbc6aba71909"
   strings:
      $s1 = "dksygVVfbkTeIdGUVEixyLtqMmKcjujzxPlmFitObhbKYCXuIlSMzOAVWal005989250882207995788329553289788902002722202072575036573058958668796" ascii
      $s2 = "IQxHzejySHKpQQYjgMzcOAWbdSKnBgzopWQVWkoFCLjbWKuRTvWXZmtqPNtzDzEjGAXPLelwQdReHHYPrDakxncyhhVWUkXEKGKmgZNzHycfGOTYrezyfZxhFqtMCptj" ascii
      $s3 = "zwdxne" fullword ascii
      $s4 = "kilpug" fullword ascii
      $s5 = ",(x.Equ" fullword ascii
      $s6 = "E zWEz=a " fullword ascii
      $s7 = "%ltEGQ)kWT%o" fullword ascii
      $s8 = "MLwx!^," fullword ascii
      $s9 = "MSSNCOIi" fullword ascii
      $s10 = "NbCo?Q" fullword ascii
      $s11 = "tAEX0\\-\"" fullword ascii
      $s12 = "g%%i0.I7" fullword ascii
      $s13 = "ibUeq\\\\" fullword ascii
      $s14 = "PelzS;>" fullword ascii
      $s15 = "Vrgj`&.f" fullword ascii
      $s16 = "w!cFTk}]y" fullword ascii
      $s17 = "XPPHXXWf" fullword ascii
      $s18 = "~pPqT)g\"hv" fullword ascii
      $s19 = "NFQu/V1" fullword ascii
      $s20 = "l?.rgA" fullword ascii
   condition:
      uint16(0) == 0x5149 and filesize < 600KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

