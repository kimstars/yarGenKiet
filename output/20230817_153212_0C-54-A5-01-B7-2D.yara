/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule AdobeCEF_dat {
   meta:
      description = "MP - file AdobeCEF.dat.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "a16856377d99a9776a08fa24d555d83d2d363602fe4d45bdaa42c818cf6c2c6b"
   strings:
      $s1 = "hgggggggg" fullword ascii /* reversed goodware string 'ggggggggh' */
      $s2 = "hggggggggggggg" fullword ascii /* reversed goodware string 'gggggggggggggh' */
      $s3 = "hgggggg" fullword ascii /* reversed goodware string 'ggggggh' */
      $s4 = "4444444444444444{{{{{{{{{{{{{{{{" fullword ascii /* hex encoded string 'DDDDDDDD' */
      $s5 = "khggggggggggggggg" fullword ascii
      $s6 = "hggggggggggggggg" fullword ascii
      $s7 = "ggggggggggi" fullword ascii
      $s8 = "hgggggggggg" fullword ascii
      $s9 = "hggggggggg" fullword ascii
      $s10 = "hgggggggggggggg" fullword ascii
      $s11 = "BIVTT -S" fullword ascii
      $s12 = "khggggg" fullword ascii
      $s13 = "hggggggggggg" fullword ascii
      $s14 = "hggggggg" fullword ascii
      $s15 = "hggggggggggggghgggggggggggggggl" fullword ascii
      $s16 = "hgggggggggggg" fullword ascii
      $s17 = ".RUTTB.UTT" fullword ascii
      $s18 = "UTTBDVTT" fullword ascii
      $s19 = "LBWSTTC" fullword ascii
      $s20 = "hgggggggggg " fullword ascii
   condition:
      uint16(0) == 0x0371 and filesize < 2000KB and
      8 of them
}

rule AdobeGenuineHelper_exe {
   meta:
      description = "MP - file AdobeGenuineHelper.exe.sc"
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
      hash1 = "4592696c943371aeea9e6a63918b984cd7a872c75dbd62026d9426e59e7dd144"
   strings:
      $s1 = "hKhDPp.dll" fullword ascii
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s3 = "cef_process_message_create" fullword ascii
      $s4 = "\\AdobeCEF.dat" fullword wide
      $s5 = " Type Descriptor'" fullword ascii
      $s6 = "operator<=>" fullword ascii
      $s7 = "operator co_await" fullword ascii
      $s8 = ".data$rs" fullword ascii
      $s9 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s10 = "cef_log" fullword ascii
      $s11 = " Base Class Descriptor at (" fullword ascii
      $s12 = " Class Hierarchy Descriptor'" fullword ascii
      $s13 = " Complete Object Locator'" fullword ascii
      $s14 = "TAbIN1" fullword ascii
      $s15 = "cef_string_map_value" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "cef_api_hash" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "cef_string_utf16_clear" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "cef_string_userfree_utf16_free" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "cef_string_utf16_to_utf8" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "cef_v8value_create_int" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_0C_54_A5_01_B7_2D_logatr {
   meta:
      description = "MP - file logatr.txt"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "1b9f176a474011e9c516be00dbd9f54a5593456f4e00d67335cf616628976169"
   strings:
      $x1 = "     %SystemRoot%\\system32\\regsvr32.exe /s /n /i:/UserInstall %SystemRoot%\\system32\\themeui.dll" fullword wide
      $x2 = "     C:\\Users\\Public\\Documents\\AgentFMC\\MiAV.exe" fullword wide
      $x3 = "     c:\\users\\public\\documents\\agentfmc\\miav.exe" fullword wide
      $x4 = "     c:\\windows\\system32\\cmd.exe" fullword wide
      $x5 = "     c:\\windows\\system32\\iconcodecservice.dll" fullword wide
      $x6 = "     c:\\windows\\system32\\systempropertiesperformance.exe" fullword wide
      $x7 = "     regsvr32.exe /s /n /i:U shell32.dll" fullword wide
      $x8 = "     c:\\windows\\system32\\shell32.dll" fullword wide
      $s9 = "     C:\\Windows\\System32\\ie4uinit.exe -UserIconConfig" fullword wide
      $s10 = "     c:\\windows\\system32\\iedkcs32.dll" fullword wide
      $s11 = "     c:\\windows\\system32\\themeui.dll" fullword wide
      $s12 = "     c:\\windows\\system32\\mscories.dll" fullword wide
      $s13 = "     c:\\windows\\system32\\userinit.exe" fullword wide
      $s14 = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" fullword wide
      $s15 = "   cmd.exe" fullword wide
      $s16 = "     cmd.exe" fullword wide
      $s17 = "     \"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Windows\\System32\\iedkcs32.dll\",BrandIEActiveSetup SIGNUP" fullword wide
      $s18 = "     %SystemRoot%\\system32\\unregmp2.exe /FirstLogon /Shortcuts /RegBrowsers /ResetMUI" fullword wide
      $s19 = "     C:\\Windows\\system32\\Rundll32.exe C:\\Windows\\system32\\mscories.dll,Install" fullword wide
      $s20 = "     c:\\windows\\system32\\rdpclip.exe" fullword wide
   condition:
      uint16(0) == 0xfeff and filesize < 20KB and
      1 of ($x*) and 4 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _AdobeGenuineHelper_exe_libcef_dll_0 {
   meta:
      description = "MP - from files AdobeGenuineHelper.exe.sc, libcef.dll.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "abcf2c8bab98cedb1bd973a0cefa747e6fe9d835248e4471f7cf9c26446abe6e"
      hash2 = "4592696c943371aeea9e6a63918b984cd7a872c75dbd62026d9426e59e7dd144"
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

