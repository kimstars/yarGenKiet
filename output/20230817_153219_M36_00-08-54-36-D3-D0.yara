/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule adobe_exe {
   meta:
      description = "MP - file adobe.exe.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "abcf2c8bab98cedb1bd973a0cefa747e6fe9d835248e4471f7cf9c26446abe6e"
   strings:
      $s1 = "amtservices.dll" fullword ascii
      $s2 = "C:\\builds\\GoCart\\5.0\\source\\gocartclient\\public\\cefhelper\\binaries\\windows\\release\\Adobe Genuine Helper.pdb" fullword ascii
      $s3 = "Adobe Genuine Helper.exe" fullword wide
      $s4 = "(Symantec SHA256 TimeStamping Signer - G2" fullword ascii
      $s5 = "cef_process_message_create" fullword ascii
      $s6 = "(Symantec SHA256 TimeStamping Signer - G20" fullword ascii
      $s7 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s8 = " Type Descriptor'" fullword ascii
      $s9 = ".?AV?$RefCountedThreadSafe@VBindStateBase@internal@base@@U?$DefaultRefCountedThreadSafeTraits@VBindStateBase@internal@base@@@3@@" ascii
      $s10 = ".?AV?$RefCountedThreadSafe@VBindStateBase@internal@base@@U?$DefaultRefCountedThreadSafeTraits@VBindStateBase@internal@base@@@3@@" ascii
      $s11 = "AMTLogLevel" fullword ascii
      $s12 = "AMTLogFormat" fullword ascii
      $s13 = "AdobeGCInvoker-1.0" fullword wide
      $s14 = "ClientRenderer.FocusedNodeChanged" fullword ascii
      $s15 = "9,9094989l9p9t9x9H:L:P:T:X:\\:`:d:h:l:p:t:x:|:" fullword ascii
      $s16 = ".?AVBindStateBase@internal@base@@" fullword ascii
      $s17 = "fil.pak" fullword ascii
      $s18 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s19 = "http://tests/" fullword ascii
      $s20 = ".?AVRefCountedThreadSafeBase@subtle@base@@" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule libcef_dll {
   meta:
      description = "MP - file libcef.dll.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "9158094314c95117c3329c7bf949ef8115e57fe11c7035ad2fa504c399127b30"
   strings:
      $s1 = "WPYYzx.dll" fullword ascii
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s3 = "cef_process_message_create" fullword ascii
      $s4 = "W\\AdobeCEF.dat" fullword wide
      $s5 = " Type Descriptor'" fullword ascii
      $s6 = "operator<=>" fullword ascii
      $s7 = ">#>5>?>a>" fullword ascii /* hex encoded string 'Z' */
      $s8 = "operator co_await" fullword ascii
      $s9 = "404=4^4c4|4" fullword ascii /* hex encoded string '@DLD' */
      $s10 = ".data$rs" fullword ascii
      $s11 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s12 = "cef_log" fullword ascii
      $s13 = " Base Class Descriptor at (" fullword ascii
      $s14 = " Class Hierarchy Descriptor'" fullword ascii
      $s15 = " Complete Object Locator'" fullword ascii
      $s16 = "cef_string_map_value" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "cef_api_hash" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "cef_string_utf16_clear" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "cef_string_userfree_utf16_free" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "cef_string_utf16_to_utf8" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule AdobeCEF_dat {
   meta:
      description = "MP - file AdobeCEF.dat.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "7b49d04b3f334b0a2925c9679868eddeeee772e8dd943d1e4717302e35aadf26"
   strings:
      $s1 = ")2)&)*)^)f)" fullword ascii /* hex encoded string '/' */
      $s2 = "'7'?'!'d'" fullword ascii /* hex encoded string '}' */
      $s3 = "&4&>&'&]&b&" fullword ascii /* hex encoded string 'K' */
      $s4 = ",4,=,&,[,A," fullword ascii /* hex encoded string 'J' */
      $s5 = "\"7\"]\"e\"" fullword ascii /* hex encoded string '~' */
      $s6 = "(3(*(C(~(" fullword ascii /* hex encoded string '<' */
      $s7 = "!: - Q E I } a " fullword ascii
      $s8 = " - S/y/" fullword ascii
      $s9 = "vutsrqp" fullword ascii
      $s10 = "%8% %\\%D%z%b%" fullword ascii
      $s11 = "gkgugtg" fullword ascii
      $s12 = "gjgrgugkgig" fullword ascii
      $s13 = "d*S*q*Q*Q*G*V*`*M*W*K*U*W*_*^*]*6*5*4*3*2*1*0*?*>*=*<*;*:*9*8*'*&*%*$*#*\"*!* */*.*-*,*+***)*(*W*d*S*a*W*Q*b*C*Y*FbrenSxdSra~tr@" ascii
      $s14 = "BFGONJNL" fullword ascii
      $s15 = "Qruebven" fullword ascii
      $s16 = "Srtrzure" fullword ascii
      $s17 = "Yxarzure" fullword ascii
      $s18 = "Xtcxure" fullword ascii
      $s19 = "Drgcrzure" fullword ascii
      $s20 = "Dvcbesvn" fullword ascii
   condition:
      uint16(0) == 0x002d and filesize < 2000KB and
      8 of them
}

rule M36_00_08_54_36_D3_D0_log_txt {
   meta:
      description = "MP - file log.txt.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "71bd54de612399b450fa215decbfe38f0fd6257ef500d2f88cbb4806bf4fde4f"
   strings:
      $x1 = " - Copy.doc-->H:\\~WRL0001.tmp--Rename Or Move File(ver.8914)--Serial: FAT32 00000000000042--2" fullword ascii
      $x2 = "2023-01-13 08:08:11--Lateral Movement--Create File in USB: 0319N2FH4MGVL3Y3; Process: C:\\Windows\\System32\\svchost.exe; Filena" ascii
      $x3 = "2023-01-13 08:08:43--Lateral Movement--Create File in USB: 0319N2FH4MGVL3Y3; Process: C:\\Windows\\System32\\svchost.exe; Filena" ascii
      $x4 = "2023-01-13 08:08:10--Lateral Movement--Create File in USB: 0319N2FH4MGVL3Y3; Process: C:\\Windows\\System32\\svchost.exe; Filena" ascii
      $x5 = "2023-01-13 08:08:10--Lateral Movement--Create File in USB: 0319N2FH4MGVL3Y3; Process: C:\\Windows\\System32\\svchost.exe; Filena" ascii
      $x6 = "2023-01-13 08:08:43--Lateral Movement--Create File in USB: 0319N2FH4MGVL3Y3; Process: C:\\Windows\\System32\\svchost.exe; Filena" ascii
      $x7 = "2023-01-13 08:08:11--Lateral Movement--Create File in USB: 0319N2FH4MGVL3Y3; Process: C:\\Windows\\System32\\svchost.exe; Filena" ascii
      $s8 = "N GIAO NAM -B? (luu CQ1).xls-->F:\\Nam 2022\\A52A0936.tmp--Rename Or Move File(ver.8914)--Serial:TOAN PK FAT32 001CC0EC34C9BC308" ascii
      $s9 = "2022-04-21 12:03:35--USB--F:\\Data\\CNPK T?NH\\TMKH PKPT Gia Lai thi -theo C?c.doc-->F:\\Data\\CNPK T?NH\\~WRL0005.tmp--Rename O" ascii
      $s10 = "2022-04-21 12:03:35--USB--F:\\Data\\CNPK T?NH\\~WRD0004.tmp-->F:\\Data\\CNPK T?NH\\TMKH PKPT Gia Lai thi -theo C?c.doc--Rename O" ascii
      $s11 = "N GIAO NAM -B? (luu CQ).xls-->F:\\Nam 2022\\45746A96.tmp--Rename Or Move File(ver.8914)--Serial:TOAN PK FAT32 001CC0EC34C9BC3087" ascii
      $s12 = "2022-04-21 12:15:28--USB--F:\\Data\\CNPK T?NH\\TMKH PKPT Gia Lai thi -theo C?c.doc-->F:\\Data\\CNPK T?NH\\~WRL0720.tmp--Rename O" ascii
      $s13 = "y Ninh thi -theo C?c.doc-->F:\\~WRL2302.tmp--Rename Or Move File(ver.8914)--Serial:GRMCULFRER_EN_DVD NTFS 4C530001300118103484--" ascii
      $s14 = "2022-04-21 14:36:12--USB--F:\\Data\\CNPK T?NH\\~WRD0000.tmp-->F:\\Data\\CNPK T?NH\\TMKH PKPT Gia Lai thi -theo C?c.doc--Rename O" ascii
      $s15 = "N GIAO NAM -B? (luu CQ).xls-->F:\\Nam 2022\\52072D9F.tmp--Rename Or Move File(ver.8914)--Serial:TOAN PK FAT32 001CC0EC34C9BC3087" ascii
      $s16 = "2022-04-21 14:35:16--USB--F:\\Data\\CNPK T?NH\\~WRD0000.tmp-->F:\\Data\\CNPK T?NH\\TMKH PKPT Gia Lai thi -theo C?c.doc--Rename O" ascii
      $s17 = "N GIAO NAM -B? (luu CQ).xls-->F:\\Nam 2022\\F0C56D48.tmp--Rename Or Move File(ver.8914)--Serial:TOAN PK FAT32 001CC0EC34C9BC3087" ascii
      $s18 = "2022-04-21 12:15:28--USB--F:\\Data\\CNPK T?NH\\~WRD3049.tmp-->F:\\Data\\CNPK T?NH\\TMKH PKPT Gia Lai thi -theo C?c.doc--Rename O" ascii
      $s19 = "N GIAO NAM -B? (luu CQ1).xls-->F:\\Nam 2022\\1F8E2B4.tmp--Rename Or Move File(ver.8914)--Serial:TOAN PK FAT32 001CC0EC34C9BC3087" ascii
      $s20 = "2022-04-21 14:35:15--USB--F:\\Data\\CNPK T?NH\\TMKH PKPT Gia Lai thi -theo C?c.doc-->F:\\Data\\CNPK T?NH\\~WRL0001.tmp--Rename O" ascii
   condition:
      uint16(0) == 0x3032 and filesize < 11000KB and
      1 of ($x*) and 4 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _adobe_exe_libcef_dll_0 {
   meta:
      description = "MP - from files adobe.exe.sc, libcef.dll.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "abcf2c8bab98cedb1bd973a0cefa747e6fe9d835248e4471f7cf9c26446abe6e"
      hash2 = "9158094314c95117c3329c7bf949ef8115e57fe11c7035ad2fa504c399127b30"
   strings:
      $s1 = "cef_process_message_create" fullword ascii
      $s2 = " Type Descriptor'" fullword ascii
      $s3 = "cef_log" fullword ascii
      $s4 = " Base Class Descriptor at (" fullword ascii
      $s5 = " Class Hierarchy Descriptor'" fullword ascii
      $s6 = " Complete Object Locator'" fullword ascii
      $s7 = "cef_string_map_value" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "cef_api_hash" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "cef_string_utf16_clear" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "cef_string_userfree_utf16_free" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "cef_string_utf16_to_utf8" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "cef_v8value_create_int" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "cef_string_map_size" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "cef_string_map_key" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "cef_string_map_append" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "cef_string_utf8_to_utf16" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "cef_cookie_manager_get_global_manager" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "cef_string_map_alloc" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "cef_string_map_free" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "cef_string_utf16_cmp" fullword ascii /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

