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
      hash1 = "ac7a229884ff97e2ecf575f44103eb9fb8a0c0e71c9092e017bd1141440f9db0"
   strings:
      $s1 = "XIjJi.dll" fullword ascii
      $s2 = "%temp%\\tmp789803676.tmp" fullword ascii
      $s3 = ";#<(<2<f<{<" fullword ascii /* hex encoded string '/' */
      $s4 = "\\lib.dat" fullword ascii
      $s5 = "qjchmngmhjhqjypsevy" fullword ascii
      $s6 = "ooyojilomvqlamhtcenauuvhmuiuljofdtqbpxthxistmim" fullword ascii
      $s7 = "blasmcxfmxaolojrfvsfsyuuy" fullword ascii
      $s8 = "fkfhlmseaqvnhncf" fullword ascii
      $s9 = "cptewxsawnxhiucofogvm" fullword ascii
      $s10 = "xqevdmyeugxlxofovqgbexodwmaxrmwrhyqgmgdon" fullword ascii
      $s11 = "lwjengypnssmnflv" fullword ascii
      $s12 = "nkhuovqvsiyinigwfxoefvmiwvyvigmt" fullword ascii
      $s13 = "stepwknls" fullword ascii
      $s14 = "ctsyywwqqyfqyksauvggkbhcebxwoaaevqogeexouyfx" fullword ascii
      $s15 = "uguqixvhwvegunajqnpmtqiqkvhhmnbmckdiegulyohycnk" fullword ascii
      $s16 = "rbbmkonaafaexpfmnyoagxdrfm" fullword ascii
      $s17 = "sdcbtiux" fullword ascii
      $s18 = "wdxxaqhmshysvpdsmqjdtksxisfdqka" fullword ascii
      $s19 = "ofsibrwgav" fullword ascii
      $s20 = "wvtjixityc" fullword ascii
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

rule LikeMustang2_lib {
   meta:
      description = "MP - file lib.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "6b1dd01b554b1a7698dc1fc0b4d98363cce4cc9717b387316c77dba1118043cc"
   strings:
      $s1 = "nNJkqmUlHMdcC6390368778295069960832860875672983237620899390757765676735292367058095277855282977568989333056793393977580268955877" ascii
      $s2 = "dcC63903687782950699608328608756729832376208993907577656767352923670580952778552829775689893330567933939775802689558778232722265" ascii
      $s3 = "RJHnUgtCACEKqbnIZMMzjPaIxIddSmmACrZfqdcYqICEiucjcTVWUMeLpyFRfjqKPmnSQdhyLQPaSHrsKvwZmzgfdVZlNQzbklWSzrojOdTAswLkoYNJXyFaqBvlkIXq" ascii
      $s4 = "zwdxne" fullword ascii
      $s5 = "kilpug" fullword ascii
      $s6 = ",(x.Equ" fullword ascii
      $s7 = "E zWEz=a " fullword ascii
      $s8 = "%ltEGQ)kWT%o" fullword ascii
      $s9 = "MLwx!^," fullword ascii
      $s10 = "MSSNCOIi" fullword ascii
      $s11 = "NbCo?Q" fullword ascii
      $s12 = "tAEX0\\-\"" fullword ascii
      $s13 = "g%%i0.I7" fullword ascii
      $s14 = "ibUeq\\\\" fullword ascii
      $s15 = "PelzS;>" fullword ascii
      $s16 = "VCgoufDMUmHJcfVkwUlanDWeKdEUjgdptHApxUGSsdKNrgUkPPyuShQAblWPhFiFBOKHHXlPetlkCvpBXjBFlduQaNRYJwRzeuqoiijqoQShPmRNupYpjulQsSGZmQux" ascii
      $s17 = "Vrgj`&.f" fullword ascii
      $s18 = "w!cFTk}]y" fullword ascii
      $s19 = "XPPHXXWf" fullword ascii
      $s20 = "~pPqT)g\"hv" fullword ascii
   condition:
      uint16(0) == 0x4a52 and filesize < 600KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

