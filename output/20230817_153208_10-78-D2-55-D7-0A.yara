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
      hash1 = "c8c2ba3316f3278fe42e0a1fc9ed5dd7a34357b241198c6e099ed6f166648c9e"
   strings:
      $s1 = "KYYYYYY" fullword ascii /* reversed goodware string 'YYYYYYK' */
      $s2 = "YYYYYV" fullword ascii /* reversed goodware string 'VYYYYY' */
      $s3 = "XYYYYY" fullword ascii /* reversed goodware string 'YYYYYX' */
      $s4 = "VHQ3Y3Y3X3Y" fullword ascii /* base64 encoded string 'Tt7cv7_v' */
      $s5 = "3Y3Y3Y" fullword ascii /* reversed goodware string 'Y3Y3Y3' */
      $s6 = "3Y3Y3M3Y3Y3Y" fullword ascii /* base64 encoded string 'cv73v7cv' */
      $s7 = "3Y3Y3U" fullword ascii /* reversed goodware string 'U3Y3Y3' */
      $s8 = "3Y3Y3Y3Y3Y3Y" fullword ascii /* base64 encoded string 'cv7cv7cv' */
      $s9 = "3Y3Y3Z3Y3Z3Y" fullword ascii /* base64 encoded string 'cv7gv7gv' */
      $s10 = "YYYYY*Y+YYYYY8Y?YtY#Y8YYY8Y+YtY8Y<YYY8Y+YtY;Y1YYY8Y+YtY=Y#YYY8Y+YtY<Y>YYY8Y+YtY0Y(YYY8Y+YtY3Y6YYY8Y+YtY2Y.YYY8Y+YtY5Y;YYY8Y+YtY5" ascii
      $s11 = "QIYYYYYYYYXYYYXYYYYYYYYYYYYYYY" fullword ascii
      $s12 = "YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY" fullword ascii
      $s13 = "HYYYYYY" fullword ascii
      $s14 = "QIYYYYYYYYYYYYYYYYYYYYYYYY" fullword ascii
      $s15 = "YYYYYYYYYYYYYYYYYYYYYYYYYXYYY" fullword ascii
      $s16 = "ZPIYYYY" fullword ascii
      $s17 = "JYYYYYY" fullword ascii
      $s18 = "QIXYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY" fullword ascii
      $s19 = "MYYYYYY" fullword ascii
      $s20 = "YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY" ascii
   condition:
      uint16(0) == 0xc0c1 and filesize < 2000KB and
      8 of them
}

rule AdobeGenuineHelpers_exe {
   meta:
      description = "MP - file AdobeGenuineHelpers.exe.sc"
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
      hash1 = "fc006b4d2336c305797d6e133a69a011dc70cd5d5a6a5f790f5f918419dff9eb"
   strings:
      $s1 = "xuKWzo.dll" fullword ascii
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

rule _AdobeGenuineHelpers_exe_libcef_dll_0 {
   meta:
      description = "MP - from files AdobeGenuineHelpers.exe.sc, libcef.dll.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "abcf2c8bab98cedb1bd973a0cefa747e6fe9d835248e4471f7cf9c26446abe6e"
      hash2 = "fc006b4d2336c305797d6e133a69a011dc70cd5d5a6a5f790f5f918419dff9eb"
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

