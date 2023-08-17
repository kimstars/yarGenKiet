/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Adobe_exe {
   meta:
      description = "MP - file Adobe.exe.sc"
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
      hash1 = "918e1d192a9b28763ac71aa1b1c0fad2be5dd2d1296d46077b0ed076015fe76f"
   strings:
      $s1 = "goZqoK.dll" fullword ascii
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
      hash1 = "a0ccadddeabe77247a46f4edb811f6ec4ae2992049a141f96ed83bdc3150fa9a"
   strings:
      $s1 = "33333333333333337777777777777777" ascii /* hex encoded string '33333333wwwwwwww' */
      $s2 = "33333333333333337777777777777777################\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"" fullword ascii /* hex encoded string '33333333wwwwwwww' */
      $s3 = "-3- -0.-.~.n/" fullword ascii
      $s4 = "-<-8-4-0-,-(-$- -\\-X-T-P-L-H-D-@-|-x-t-p-l-h-d-`-" fullword ascii
      $s5 = "[yh_srospy_L" fullword ascii
      $s6 = "o!X!z!Z!Z!L!]!k!F!\\!@!^!\\!T!U!V!=!>!?!8!9!:!;!4!5!6!7!0!1!2!3!,!-!.!/!(!)!*!+!$!%!&!'! !!!\"!#!\\!o!X!j!\\!Z!i!H!R!MiyneXsoXyj" ascii
      $s7 = "* *^*r*" fullword ascii
      $s8 = "[yh_srospyQsxy" fullword ascii
      $s9 = "Knuhy_srospyK" fullword ascii
      $s10 = "-8-0-(- -X-P-H-@-x-p-h-`-" fullword ascii
      $s11 = "-6-+-_-c-" fullword ascii /* hex encoded string 'l' */
      $s12 = "lhlmlsljlhlalklvlelelgl" fullword ascii
      $s13 = "$ %I%z%" fullword ascii
      $s14 = "%9%!%Y%Q%{%d%" fullword ascii
      $s15 = "+5%_%D%B%" fullword ascii
      $s16 = "*\"+;%'%}%i%" fullword ascii
      $s17 = "$3$\"$4%/%D%@&" fullword ascii
      $s18 = "%$%D%d%" fullword ascii
      $s19 = "$4%&%S%I%@%b%" fullword ascii
      $s20 = "IMLDEAEG" fullword ascii
   condition:
      uint16(0) == 0xf990 and filesize < 2000KB and
      8 of them
}

rule A0_8C_FD_E9_E7_42_log_txt {
   meta:
      description = "MP - file log.txt.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "a59caaf1d285462a5723a0473699965d4ff2940c1ed7e15509bf288c37b9dfd5"
   strings:
      $x1 = "2022-10-03 11:13:56--Create File--Process: C:\\Windows\\System32\\taskhost.exe; FileName: C:\\Windows\\TEMP\\SDIAG_b513ad6a-4a75" ascii
      $x2 = "2022-09-12 06:23:33--Create File--Process: C:\\Windows\\System32\\taskhost.exe; FileName: C:\\Windows\\TEMP\\SDIAG_69f50199-5937" ascii
      $x3 = "2022-09-19 01:00:00--Create File--Process: C:\\Windows\\System32\\taskhost.exe; FileName: C:\\Windows\\TEMP\\SDIAG_97f80455-b02b" ascii
      $x4 = "2022-09-26 07:42:27--Create File--Process: C:\\Windows\\System32\\taskhost.exe; FileName: C:\\Windows\\TEMP\\SDIAG_ce58e117-3f1d" ascii
      $x5 = "2022-09-18 01:00:00--Create File--Process: C:\\Windows\\System32\\taskhost.exe; FileName: C:\\Windows\\TEMP\\SDIAG_b0eed8d6-c30d" ascii
      $x6 = "2022-10-03 11:13:56--Create File--Process: C:\\Windows\\System32\\taskhost.exe; FileName: C:\\Windows\\TEMP\\SDIAG_b513ad6a-4a75" ascii
      $x7 = "2022-09-26 07:42:27--Create File--Process: C:\\Windows\\System32\\taskhost.exe; FileName: C:\\Windows\\TEMP\\SDIAG_ce58e117-3f1d" ascii
      $x8 = "2022-09-12 06:23:33--Create File--Process: C:\\Windows\\System32\\taskhost.exe; FileName: C:\\Windows\\TEMP\\SDIAG_69f50199-5937" ascii
      $x9 = "2022-09-19 01:00:00--Create File--Process: C:\\Windows\\System32\\taskhost.exe; FileName: C:\\Windows\\TEMP\\SDIAG_97f80455-b02b" ascii
      $x10 = "2022-09-18 01:00:00--Create File--Process: C:\\Windows\\System32\\taskhost.exe; FileName: C:\\Windows\\TEMP\\SDIAG_b0eed8d6-c30d" ascii
      $x11 = "2022-09-27 10:30:35--Create File--Process: C:\\Windows\\System32\\msdt.exe; FileName: C:\\Windows\\TEMP\\SDIAG_f20d9db9-159e-418" ascii
      $x12 = "2022-10-18 14:10:23--Lateral Movement--Create File in USB: AAZ6V7GJGZKDXP8K; Process: C:\\Windows\\SysWOW64\\dllhost.exe; Filena" ascii
      $x13 = "2022-10-21 09:20:37--Lateral Movement--Create File in USB: AAZ6V7GJGZKDXP8K; Process: C:\\Windows\\SysWOW64\\dllhost.exe; Filena" ascii
      $x14 = "2022-10-19 16:07:43--Lateral Movement--Create File in USB: AAZ6V7GJGZKDXP8K; Process: C:\\Windows\\SysWOW64\\dllhost.exe; Filena" ascii
      $x15 = "2022-10-18 14:10:21--Lateral Movement--Create File in USB: AAZ6V7GJGZKDXP8K; Process: C:\\Windows\\SysWOW64\\dllhost.exe; Filena" ascii
      $x16 = "2022-10-18 11:32:35--Lateral Movement--Create File in USB: AAZ6V7GJGZKDXP8K; Process: C:\\Windows\\SysWOW64\\dllhost.exe; Filena" ascii
      $x17 = "2022-10-18 12:38:12--Lateral Movement--Create File in USB: AAZ6V7GJGZKDXP8K; Process: C:\\Windows\\SysWOW64\\dllhost.exe; Filena" ascii
      $x18 = "2022-10-19 08:58:41--Lateral Movement--Create File in USB: AAZ6V7GJGZKDXP8K; Process: C:\\Windows\\SysWOW64\\dllhost.exe; Filena" ascii
      $x19 = "2022-10-17 07:29:48--Lateral Movement--Create File in USB: AAZ6V7GJGZKDXP8K; Process: C:\\Windows\\SysWOW64\\dllhost.exe; Filena" ascii
      $x20 = "2022-10-17 07:21:42--Lateral Movement--Create File in USB: AAZ6V7GJGZKDXP8K; Process: C:\\Windows\\SysWOW64\\dllhost.exe; Filena" ascii
   condition:
      uint16(0) == 0x3032 and filesize < 800KB and
      1 of ($x*)
}

/* Super Rules ------------------------------------------------------------- */

rule _Adobe_exe_libcef_dll_0 {
   meta:
      description = "MP - from files Adobe.exe.sc, libcef.dll.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "abcf2c8bab98cedb1bd973a0cefa747e6fe9d835248e4471f7cf9c26446abe6e"
      hash2 = "918e1d192a9b28763ac71aa1b1c0fad2be5dd2d1296d46077b0ed076015fe76f"
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

