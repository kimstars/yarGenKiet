/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_1_1 {
   meta:
      description = "MP - file 1.bat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "cb7ed42be052c9ddfc68e9b32b341ae3e9bdc16850f5810d77783d8941368c93"
   strings:
      $x1 = "copy /y %~dp0libcef.dll %temp%\\libcef.dll" fullword ascii
      $x2 = "start /b %temp%\\1.exe H:\\DUCTHANH_PTS\\ %~dp0" fullword ascii
      $x3 = "copy /y %~dp01.exe %temp%\\1.exe" fullword ascii
      $s4 = "copy /y %~dp0..\\2\\AdobeCEF.dat %temp%\\AdobeCEF.dat" fullword ascii
   condition:
      uint16(0) == 0x6f63 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule sig_1_1_2 {
   meta:
      description = "MP - file 1.exe"
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

rule sig_1_libcef {
   meta:
      description = "MP - file libcef.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "034eca8e5ad2a262510db7680ce6c10d5d0e24685b70bfcf3cab910473afc5a5"
   strings:
      $s1 = "fLmAmM.dll" fullword ascii
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s3 = "cef_process_message_create" fullword ascii
      $s4 = " Type Descriptor'" fullword ascii
      $s5 = "operator<=>" fullword ascii
      $s6 = "operator co_await" fullword ascii
      $s7 = ".data$rs" fullword ascii
      $s8 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s9 = "cef_log" fullword ascii
      $s10 = " Base Class Descriptor at (" fullword ascii
      $s11 = " Class Hierarchy Descriptor'" fullword ascii
      $s12 = " Complete Object Locator'" fullword ascii
      $s13 = "cef_string_map_value" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "cef_api_hash" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "cef_string_utf16_clear" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "cef_string_userfree_utf16_free" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "cef_string_utf16_to_utf8" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "cef_v8value_create_int" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "cef_string_map_size" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "cef_string_map_key" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _1_libcef_0 {
   meta:
      description = "MP - from files 1.exe, libcef.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "abcf2c8bab98cedb1bd973a0cefa747e6fe9d835248e4471f7cf9c26446abe6e"
      hash2 = "034eca8e5ad2a262510db7680ce6c10d5d0e24685b70bfcf3cab910473afc5a5"
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

