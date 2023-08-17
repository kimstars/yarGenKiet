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
      hash1 = "8f0983c8a757c8c51d8265c2d785512f03eb3ff6daed0dd885a9a224e10a9a57"
   strings:
      $s1 = "YXeayE.dll" fullword ascii
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
      $s14 = "cef_string_map_value" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "cef_api_hash" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "cef_string_utf16_clear" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "cef_string_userfree_utf16_free" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "cef_string_utf16_to_utf8" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "cef_v8value_create_int" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "cef_string_map_size" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule AdobeCEF_dat {
   meta:
      description = "MP - file AdobeCEF.dat.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "61245b652b64ebf5b42ec7406a2887dd59e960aa2b6324b9b73b44e567bd2bcf"
   strings:
      $s1 = "+(65%21*#" fullword ascii /* hex encoded string 'e!' */
      $s2 = "-->?;;O" fullword ascii
      $s3 = "- 8;;E=" fullword ascii
      $s4 = ", -N/;;O" fullword ascii
      $s5 = "- :;;;" fullword ascii
      $s6 = " -+:;;O" fullword ascii
      $s7 = "- >;;I@" fullword ascii
      $s8 = "- 9;;E=" fullword ascii
      $s9 = " -@8;;O" fullword ascii
      $s10 = ",*V;;- " fullword ascii
      $s11 = "- <;;O" fullword ascii
      $s12 = "- 9;;M" fullword ascii
      $s13 = "- 8;;O" fullword ascii
      $s14 = "&_- .;;O" fullword ascii
      $s15 = "ko -b0;;I@" fullword ascii
      $s16 = "- <;;O@" fullword ascii
      $s17 = "- ?;;O" fullword ascii
      $s18 = "- :;;O" fullword ascii
      $s19 = " -;8;;" fullword ascii
      $s20 = "DEFG@ABCLM" fullword ascii
   condition:
      uint16(0) == 0xe8f5 and filesize < 2000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _adobe_exe_libcef_dll_0 {
   meta:
      description = "MP - from files adobe.exe.sc, libcef.dll.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "abcf2c8bab98cedb1bd973a0cefa747e6fe9d835248e4471f7cf9c26446abe6e"
      hash2 = "8f0983c8a757c8c51d8265c2d785512f03eb3ff6daed0dd885a9a224e10a9a57"
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

