/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule aro_aro {
   meta:
      description = "MP - file aro.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "4a53e45111565912353590d4da6618c6b56653546f1e65d7f262dcff26548eb0"
   strings:
      $s1 = "cfPnhJHDqMLVLdbFGAhumvEOpXBdGNXizaCHtDdPNhvMaDvK37763506525580636827953777272893899035876525052868097276737053969967298227723389" ascii
      $s2 = "* M\"\\IQ" fullword ascii
      $s3 = "3vAp -" fullword ascii
      $s4 = "FTvBz_cM8V6j" fullword ascii
      $s5 = "JDMRjG$" fullword ascii
      $s6 = "jjTjoU]" fullword ascii
      $s7 = "MTYwwZnIfIzyHxEyfaLZjzgpdPYFubjEVzvyMGZRyirLviZIPFPILXnvhFAnnAutTakBVMIvbnYfMUzsVErLyTiPpBpaenXFCwVaaPzLCXafhDAVuOsJRySOYjflALPt" ascii
      $s8 = "0^IfXk{>C" fullword ascii
      $s9 = "WvRYvuKxYfJWxTnxoTsXMlvKvGbUcIViMhLteWcxSrIgedPaSiTlhsqIrZdDxoTOkKWkoCUcwgIbNjwJypQiGIbwBaCNCjJQKlZDvVsnUGkRwpCDyrhWZBxaVzjCsYlc" ascii
      $s10 = "bDhO!:g" fullword ascii
      $s11 = "8LkSxqVO" fullword ascii
      $s12 = "YTuZ0Up" fullword ascii
      $s13 = "vhTqPxB" fullword ascii
      $s14 = "mqkH3z(" fullword ascii
      $s15 = "pSaW=^3" fullword ascii
      $s16 = "PbokN94Ij" fullword ascii
      $s17 = "ZOBzw:e" fullword ascii
      $s18 = "lJbg20~h" fullword ascii
      $s19 = "XPPHXXWf" fullword ascii
      $s20 = "HhNnJBDdYOnSKKaGWZgKhtvVhbralMjkKjwLFDWEBXMhleBfIfZYtULomQoViVTrvanUttmVYFMSpbqsPVBcthHDjdEWKSVxVBDGjtsTlGGVHswmwkvSMoSBFpLSFXXd" ascii
   condition:
      uint16(0) == 0x6848 and filesize < 600KB and
      8 of them
}

rule aro_aro_2 {
   meta:
      description = "MP - file aro.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "18a98c2d905a1da1d9d855e86866921e543f4bf8621faea05eb14d8e5b23b60c"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
      $s2 = "ncy><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processor" ascii
      $s3 = "aross.dll" fullword ascii
      $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
      $s5 = "AROTutorial.exe" fullword wide
      $s6 = "Support.com, Inc.1>0<" fullword ascii
      $s7 = "Support.com, Inc.0" fullword ascii
      $s8 = "http://www.support.com0" fullword ascii
      $s9 = " 2008-2012 Support.com, Inc. All rights reserved." fullword wide
      $s10 = "            <requestedExecutionLevel level=\"asinvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s11 = "re=\"*\" name=\"ARO 2011\" type=\"win32\"></assemblyIdentity><description>Advanced Registry Optimizer - Tutorial</description><d" ascii
      $s12 = " http://crl.verisign.com/pca3.crl0)" fullword ascii
      $s13 = "urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges>" fullword ascii
      $s14 = "ecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\"></assemblyIdentity></dependentAssembly></dependency><trustInfo x" ascii
      $s15 = " constructor or from DllMain." fullword ascii
      $s16 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii
      $s17 = "ZYXBFED" fullword ascii
      $s18 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii
      $s19 = "8.0.12.0" fullword wide
      $s20 = "SPRTDEV4" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule aro_aross {
   meta:
      description = "MP - file aross.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "7f1890a263b387dd6fe6e21755685caf19f567c28774d09bb2a8c72df0cc4d95"
   strings:
      $s1 = "aross.dll" fullword ascii
      $s2 = "aro.dat" fullword wide
      $s3 = "TMonitor.PWaitingThreadp" fullword ascii
      $s4 = "lmnpruvxacegiklnprtvxyc" fullword ascii
      $s5 = "mnpqtvxacefijmnprtvxycdfi" fullword ascii
      $s6 = "ijknprtuxybdfhjkn" fullword ascii
      $s7 = "yybdfhjlnprsvwybdfhjknoqsuwybdehilmoqsuwyacegi" fullword ascii
      $s8 = "mnortvxacdghkloprtvxabdfhj" fullword ascii
      $s9 = "defhjln" fullword ascii
      $s10 = "xabdfijlnprtvwybdfhimnqrtvxacefikmnprtvxycdgh" fullword ascii
      $s11 = "yacegiklopstvxacefijmnprtvwabefhjlnpqtuxybdfhjln" fullword ascii
      $s12 = "pqrtvyadegikmoqrtvxacdghklnprt" fullword ascii
      $s13 = "wwybefhjlnprsvwabdfhjlnpqtuxybdfhikmoqstwx" fullword ascii
      $s14 = "klmoqtuwybdehilmoqsuw" fullword ascii
      $s15 = "rsuvybcfgjkmoqruwybdfgjkmoqrvxaceg" fullword ascii
      $s16 = "fgjknpqtuxyb" fullword ascii
      $s17 = "pqstwybdfhjloqstwxacegiklnprtv" fullword ascii
      $s18 = "uvwybefikmoqstwxbdfgjlnprtuxycdfhjlnprsu" fullword ascii
      $s19 = "ghjknpqtuwybdf" fullword ascii
      $s20 = "lmnpsuwybdfgjkmoruvxace" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

