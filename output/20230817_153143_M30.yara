/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule M30_log_txt {
   meta:
      description = "MP - file log.txt.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "39089a3077656e60318ab2cdc922e6e9e397c9fe96d5fbd2820c8d6c82461076"
   strings:
      $x1 = "2022-09-21 07:33:24--Persistence--Set Value Registry: Process: \\Device\\HarddiskVolume3\\TMKH\\DIEN TAP\\DI?N T?P KVPT T?NH KON" ascii
      $x2 = "2022-09-29 08:51:02--Persistence--Set Value Registry: Process: \\Device\\HarddiskVolume3\\TMKH\\DIEN TAP\\DI?N T?P KVPT T?NH KON" ascii
      $x3 = "2022-09-12 08:40:30--Persistence--Set Value Registry: Process: \\Device\\HarddiskVolume3\\TMKH\\Hanh dong c?a CNHC (ct) - 2022.e" ascii
      $x4 = "2022-09-15 19:54:50--Persistence--Set Value Registry: Process: \\Device\\HarddiskVolume3\\TMKH\\DIEN TAP\\DI?N T?P KVPT T?NH KON" ascii
      $x5 = "2022-09-29 08:53:08--Persistence--Set Value Registry: Process: \\Device\\HarddiskVolume3\\TMKH\\DIEN TAP\\DI?N T?P KVPT T?NH KON" ascii
      $x6 = "2022-09-29 08:49:55--Persistence--Set Value Registry: Process: \\Device\\HarddiskVolume3\\TMKH\\DIEN TAP\\DI?N T?P KVPT T?NH KON" ascii
      $x7 = "2022-09-12 09:03:30--Persistence--Set Value Registry: Process: \\Device\\HarddiskVolume3\\TMKH\\CNHC KT-22\\Hanh dong c?a CNHC (" ascii
      $x8 = "2022-09-12 09:38:39--Persistence--Set Value Registry: Process: \\Device\\HarddiskVolume3\\TMKH\\CNHC KT-22\\Hanh dong c?a CNHC (" ascii
      $x9 = "2022-09-12 09:11:22--Persistence--Set Value Registry: Process: \\Device\\HarddiskVolume3\\TMKH\\CNHC KT-22\\Hanh dong c?a CNHC (" ascii
      $x10 = "2022-08-17 10:40:30--Discovery--Run Command Line: CreatingProcess: C:\\Users\\Asus\\Desktop\\TA-21_1.0.43_Windows -32bit.exe; Co" ascii
      $x11 = "2022-08-17 10:40:31--Discovery--Run Command Line: CreatingProcess: C:\\Users\\Asus\\Desktop\\TA-21_1.0.43_Windows -32bit.exe; Co" ascii
      $x12 = "2022-08-17 10:40:46--Discovery--Run Command Line: CreatingProcess: C:\\Users\\Asus\\Desktop\\TA-21_1.0.43_Windows -32bit.exe; Co" ascii
      $x13 = "2022-08-17 10:40:46--Discovery--Run Command Line: CreatingProcess: C:\\Users\\Asus\\Desktop\\TA-21_1.0.43_Windows -32bit.exe; Co" ascii
      $x14 = "2022-08-17 10:40:31--Discovery--Run Command Line: CreatingProcess: C:\\Users\\Asus\\Desktop\\TA-21_1.0.43_Windows -32bit.exe; Co" ascii
      $x15 = "2022-09-09 10:10:18--Lateral Movement--Create File in USB: ; Process: C:\\Users\\Asus\\AppData\\Roaming\\RAC\\mls.exe; Filename:" ascii
      $x16 = "2022-09-09 15:21:54--Lateral Movement--Create File in USB: ; Process: C:\\Users\\Asus\\AppData\\Roaming\\RAC\\mls.exe; Filename:" ascii
      $x17 = "2022-09-11 09:38:24--Lateral Movement--Create File in USB: ; Process: C:\\Users\\Asus\\AppData\\Roaming\\RAC\\mls.exe; Filename:" ascii
      $x18 = "2022-09-12 08:36:04--Lateral Movement--Create File in USB: C47DA539; Process: C:\\Users\\Asus\\AppData\\Roaming\\RAC\\mls.exe; F" ascii
      $x19 = "2022-09-09 10:10:17--Lateral Movement--Create File in USB: ; Process: C:\\Users\\Asus\\AppData\\Roaming\\RAC\\mls.exe; Filename:" ascii
      $x20 = "2022-09-09 08:13:57--Lateral Movement--Create File in USB: ; Process: C:\\Users\\Asus\\AppData\\Roaming\\RAC\\mls.exe; Filename:" ascii
   condition:
      uint16(0) == 0x3032 and filesize < 2000KB and
      1 of ($x*)
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
      hash1 = "39e58cd6d6b491d01f2691338103b688a36add271ea94fab8e99a8742ec1d9dd"
   strings:
      $s1 = "pWZOrENJwmm.dll" fullword ascii
      $s2 = " Type Descriptor'" fullword ascii
      $s3 = "bqmqmpwrhbwkiwvdrnpejwlppnbncbcibagyylpjdajauoo" fullword ascii
      $s4 = "nxqwrewyuvhfrwrfxwrwaiejflvoxutntmsoaiptpacrv" fullword ascii
      $s5 = "kcpecvxyggw" fullword ascii
      $s6 = " Class Hierarchy Descriptor'" fullword ascii
      $s7 = " Base Class Descriptor at (" fullword ascii
      $s8 = " Complete Object Locator'" fullword ascii
      $s9 = "StartProtect" fullword ascii
      $s10 = "6C7k7y7%9C9\\9c9k9p9t9x9" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "2&3<3u3" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "<=Q=X=\\=`=d=h=l=p=t=" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "5 5(5@5P5T5h5l5|5" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "7'858;8w8" fullword ascii /* Goodware String - occured 1 times */
      $s15 = ";,;3;;;@;D;H;q;" fullword ascii /* Goodware String - occured 1 times */
      $s16 = " delete[]" fullword ascii
      $s17 = "4\\8`8d8h8l8p8t8x8|8" fullword ascii /* Goodware String - occured 2 times */
      $s18 = "D$$UVP" fullword ascii /* Goodware String - occured 2 times */
      $s19 = "6Q6V6]6" fullword ascii /* Goodware String - occured 2 times */
      $s20 = " delete" fullword ascii
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
      hash1 = "2fdf1adfac7a12e0a2fa06e89778459083114961b6a6b5e129407892c272c30f"
   strings:
      $s1 = "9aaslcpzoukurnaaslcpzoukurnaaslcpzoukurnaaslcpzoukurnaaslcpzoukurnaaslcpzoukurnaaslcpzoukurnaaslcpzoukurnaaslcpzoukurnaaslcpzouk" ascii
      $s2 = "4pzoukurnaaslcpzoukurnaaslcpzoukurnaaslcpzoukurnaaslcpzoukurnaaslcpzoukurnaaslcpzoukurnaaslcpzoukurnaaslcpzoukurnaaslcpzoukurnaa" ascii
      $s3 = "_sGeTzFKV\\OX@*@%[" fullword ascii
      $s4 = "kurbaas" fullword ascii
      $s5 = "cpzyuku" fullword ascii
      $s6 = "waslcpz" fullword ascii
      $s7 = "iaslcpzo" fullword ascii
      $s8 = "lcpxouk" fullword ascii
      $s9 = "xaslcpzoukurn" fullword ascii
      $s10 = "gkurnaa" fullword ascii
      $s11 = "upzouku" fullword ascii
      $s12 = "rnaaslcpzoukurnaaslcpzoukurnaaslcpzoukurnaaslc" fullword ascii
      $s13 = "rnaaslcp" fullword ascii
      $s14 = "noukurn" fullword ascii
      $s15 = "rpzouku" fullword ascii
      $s16 = "urnaasl" fullword ascii
      $s17 = "fnaaslc" fullword ascii
      $s18 = "aslcpupu" fullword ascii
      $s19 = "yukurna" fullword ascii
      $s20 = "ukuqnaazlcp" fullword ascii
   condition:
      uint16(0) == 0x7361 and filesize < 1000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

