/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule info_SmadavHelper_exe {
   meta:
      description = "MP - file info_SmadavHelper.exe.txt"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "cbfd1b3670bdf1391f82638cad4e7ead2ab91df200b8278d46cf87c3d8f5854d"
   strings:
      $s1 = "C:\\ProgramData\\SmadavDBb\\SmadavHelper.exe: HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword ascii
      $s2 = "SmadavHelper.exe" fullword ascii
      $s3 = "Account Owner: ADMIN:Admin" fullword ascii
      $s4 = "STANDARD FILE TIME:" fullword ascii
      $s5 = "SmadavDBb" fullword ascii
      $s6 = "FILETIME:" fullword ascii
      $s7 = "File Modified Time (ATime): 2021-11-17 16:18:24" fullword ascii
      $s8 = "File Modified Time (ATime): 2021-7-23 9:59:12" fullword ascii
      $s9 = "File Create Time (CTime): 2021-11-17 9:18:24" fullword ascii
      $s10 = "MFT FILE TIME:" fullword ascii
      $s11 = "MFT Entry modified Time (MTime): 2021-11-17 16:18:24" fullword ascii
      $s12 = "File Last Access Time (RTime): 2021-11-17 16:18:24" fullword ascii
      $s13 = "File Create Time (CTime): 2021-11-17 16:18:24" fullword ascii
      $s14 = "File Last Access Time (RTime): 2021-11-17 9:18:24" fullword ascii
      $s15 = "REGISTRY LAST WRITE TIME:" fullword ascii
      $s16 = "2022-6-13 1:31:13" fullword ascii
   condition:
      uint16(0) == 0x4946 and filesize < 2KB and
      8 of them
}

rule info_SmadDB_dat {
   meta:
      description = "MP - file info_SmadDB.dat.txt"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "41037391c656a4b38b686a13406d3fa3d5353d592306421211a20b6ac7e1c194"
   strings:
      $s1 = "SmadDB.dat" fullword ascii
      $s2 = "Account Owner: ADMIN:Admin" fullword ascii
      $s3 = "STANDARD FILE TIME:" fullword ascii
      $s4 = "FILETIME:" fullword ascii
      $s5 = "File Modified Time (ATime): 2021-11-17 16:18:24" fullword ascii
      $s6 = "File Modified Time (ATime): 2021-7-23 9:59:12" fullword ascii
      $s7 = "File Create Time (CTime): 2021-11-17 9:18:24" fullword ascii
      $s8 = "MFT FILE TIME:" fullword ascii
      $s9 = "MFT Entry modified Time (MTime): 2021-11-17 16:18:24" fullword ascii
      $s10 = "File Last Access Time (RTime): 2021-11-17 16:18:24" fullword ascii
      $s11 = "File Create Time (CTime): 2021-11-17 16:18:24" fullword ascii
      $s12 = "File Last Access Time (RTime): 2021-11-17 9:18:24" fullword ascii
      $s13 = "REGISTRY LAST WRITE TIME:" fullword ascii
   condition:
      uint16(0) == 0x4946 and filesize < 1KB and
      8 of them
}

rule info_SmadHook32c_dll {
   meta:
      description = "MP - file info_SmadHook32c.dll.txt"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "2eaca6b9a8da8398bc082164699c618de007870f0b1856c444883fbf557a7dff"
   strings:
      $s1 = "SmadHook32c.dll" fullword ascii
      $s2 = "Account Owner: ADMIN:Admin" fullword ascii
      $s3 = "STANDARD FILE TIME:" fullword ascii
      $s4 = "FILETIME:" fullword ascii
      $s5 = "File Modified Time (ATime): 2021-11-17 16:18:24" fullword ascii
      $s6 = "File Modified Time (ATime): 2021-7-23 9:59:12" fullword ascii
      $s7 = "File Create Time (CTime): 2021-11-17 9:18:24" fullword ascii
      $s8 = "MFT FILE TIME:" fullword ascii
      $s9 = "MFT Entry modified Time (MTime): 2021-11-17 16:18:24" fullword ascii
      $s10 = "File Last Access Time (RTime): 2021-11-17 16:18:24" fullword ascii
      $s11 = "File Create Time (CTime): 2021-11-17 16:18:24" fullword ascii
      $s12 = "File Last Access Time (RTime): 2021-11-17 9:18:24" fullword ascii
      $s13 = "REGISTRY LAST WRITE TIME:" fullword ascii
   condition:
      uint16(0) == 0x4946 and filesize < 1KB and
      8 of them
}

rule SmadavHelper_exe {
   meta:
      description = "MP - file SmadavHelper.exe.sc"
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

rule SmadHook32c_dll {
   meta:
      description = "MP - file SmadHook32c.dll.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "fbb0eecaeff2944a1e1c531015384a062b847706b7b720c5ba2d794a48affbd6"
   strings:
      $s1 = "EKRtpNMzONC.dll" fullword ascii
      $s2 = " Type Descriptor'" fullword ascii
      $s3 = "eareheasxjlxvwojsercthnwpuqoikk" fullword ascii
      $s4 = "yypgvsdg" fullword ascii
      $s5 = "muwsuhchohmtoxnrkrmnyn" fullword ascii
      $s6 = "pewsltj" fullword ascii
      $s7 = "olshjupkohsdbfvjkiblekpnxnfcjslvucxooe" fullword ascii
      $s8 = "rifhvgykbmqgfsacroemhjxqbyss" fullword ascii
      $s9 = "fmaylvhdrlrmjlggociioxjwhq" fullword ascii
      $s10 = "lgsqxsahewfinbfkxyfipjhfuhchwixfixwfgbeo" fullword ascii
      $s11 = ":$:D:P:T:X:\\:" fullword ascii
      $s12 = " Class Hierarchy Descriptor'" fullword ascii
      $s13 = " Base Class Descriptor at (" fullword ascii
      $s14 = " Complete Object Locator'" fullword ascii
      $s15 = "StartProtect" fullword ascii
      $s16 = "7\"8J8P8" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "8C9P9x9" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "5&585J5" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "2B3H3L3P3T3" fullword ascii /* Goodware String - occured 1 times */
      $s20 = " delete[]" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule SmadDB_dat {
   meta:
      description = "MP - file SmadDB.dat.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "3d7c97e8aff0005b8ca22982c4093208faaecaf543b2949125dc8675a9d68211"
   strings:
      $s1 = "QicmWEU9bf" fullword ascii /* base64 encoded string 'B'&XE=m' */
      $s2 = "QicmWEU9b" fullword ascii /* base64 encoded string 'B'&XE=' */
      $s3 = "5UeWuTMHnPVQicmWJJybiWWoUeWuTMHnPVQicmWJJybiWWoUeWuTMHnPVQicmWJJybiWWoUeWuTMHnPVQicmWJJybiWWoUeWuTMHnPVQicmWJJybiWWoUeWuTMHnPVQi" ascii
      $s4 = "acmzB+ " fullword ascii
      $s5 = "rqhcmbp" fullword ascii
      $s6 = "mrJ.ybi" fullword ascii
      $s7 = "KQ]b`Xm\\fGgy}Xg.hXQ^0" fullword ascii
      $s8 = "SuJuTMp" fullword ascii
      $s9 = "m9JtybiWWAUKW[TMHdP\\QicmWJJyb$W>o6e%u;M;n?V7i" fullword ascii
      $s10 = "KXRPVQE" fullword ascii
      $s11 = "W0JybiW2o eWuTM%n;VQicm6J,ybiWW" fullword ascii
      $s12 = "yGieWAUWW-ThH\\PxQ[c5WJJ%b-W8o6e\"u9M-n>V%i" fullword ascii
      $s13 = "bIW2o'e%u;M:npVQicm" fullword ascii
      $s14 = "Q4W2p0C" fullword ascii
      $s15 = "\\P%RrD%" fullword ascii
      $s16 = "FmPWox3" fullword ascii
      $s17 = "nnxbiv" fullword ascii
      $s18 = "biWWoUeWu2" fullword ascii
      $s19 = "gmWgSU4" fullword ascii
      $s20 = "LZtbiW7" fullword ascii
   condition:
      uint16(0) == 0x6279 and filesize < 1000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _info_SmadavHelper_exe_info_SmadDB_dat_info_SmadHook32c_dll_0 {
   meta:
      description = "MP - from files info_SmadavHelper.exe.txt, info_SmadDB.dat.txt, info_SmadHook32c.dll.txt"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "cbfd1b3670bdf1391f82638cad4e7ead2ab91df200b8278d46cf87c3d8f5854d"
      hash2 = "41037391c656a4b38b686a13406d3fa3d5353d592306421211a20b6ac7e1c194"
      hash3 = "2eaca6b9a8da8398bc082164699c618de007870f0b1856c444883fbf557a7dff"
   strings:
      $s1 = "Account Owner: ADMIN:Admin" fullword ascii
      $s2 = "STANDARD FILE TIME:" fullword ascii
      $s3 = "FILETIME:" fullword ascii
      $s4 = "File Modified Time (ATime): 2021-11-17 16:18:24" fullword ascii
      $s5 = "File Modified Time (ATime): 2021-7-23 9:59:12" fullword ascii
      $s6 = "File Create Time (CTime): 2021-11-17 9:18:24" fullword ascii
      $s7 = "MFT FILE TIME:" fullword ascii
      $s8 = "MFT Entry modified Time (MTime): 2021-11-17 16:18:24" fullword ascii
      $s9 = "File Last Access Time (RTime): 2021-11-17 16:18:24" fullword ascii
      $s10 = "File Create Time (CTime): 2021-11-17 16:18:24" fullword ascii
      $s11 = "File Last Access Time (RTime): 2021-11-17 9:18:24" fullword ascii
      $s12 = "REGISTRY LAST WRITE TIME:" fullword ascii
   condition:
      ( uint16(0) == 0x4946 and filesize < 2KB and ( 8 of them )
      ) or ( all of them )
}

