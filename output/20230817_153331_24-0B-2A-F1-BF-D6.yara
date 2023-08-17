/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule WINWORD_exe {
   meta:
      description = "MP - file WINWORD.exe.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "6933305d924b45236a5b5089dccafa8fd43aa039e2428a9998c030ab950ef4ef"
   strings:
      $s1 = " Office Word</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.VC80.CRT\" version=\"" ascii
      $s2 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><noInherit></noInherit><assemblyIdentity processorA" ascii
      $s3 = "wwlib.dll" fullword wide
      $s4 = "wwlibcxm.dll" fullword wide
      $s5 = "WinWord.exe" fullword wide
      $s6 = "MSO.DllGetLCID" fullword ascii
      $s7 = "0608.0\" processorArchitecture=\"x86\" publicKeyToken=\"1fc8b3b9a1e18e3b\"></assemblyIdentity></dependentAssembly></dependency><" ascii
      $s8 = "5555544444" ascii /* hex encoded string 'UUTDD' */
      $s9 = "333333333337" ascii /* hex encoded string '333337' */
      $s10 = "t:\\word\\x86\\ship\\0\\winword.pdb" fullword ascii
      $s11 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><noInherit></noInherit><assemblyIdentity processorA" ascii
      $s12 = "3333555757" ascii /* hex encoded string '33UWW' */
      $s13 = "tecture=\"x86\" type=\"win32\" name=\"winword\" version=\"1.0.0.0\"></assemblyIdentity><description>Microsoft" fullword ascii
      $s14 = " Office Word</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.VC80.CRT\" version=\"" ascii
      $s15 = "wdCommandDispatch" fullword ascii
      $s16 = "6\\ship\\0\\winword.exe\\bbtopt\\winwordO.pdb" fullword ascii
      $s17 = "M$$$$$" fullword ascii /* reversed goodware string '$$$$$M' */
      $s18 = "''''''''*******++++77777777797(7" fullword ascii /* hex encoded string 'wwwwyw' */
      $s19 = "\"\"\"\"%%%%3333555757" fullword ascii /* hex encoded string '33UWW' */
      $s20 = "uuussnn" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule wwlib_dll {
   meta:
      description = "MP - file wwlib.dll.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "cb0a67ee09029f9e5b4eb0923b7e8934a484b46add1e214292376f07ad0933fb"
   strings:
      $s1 = "wwlib.dll" fullword ascii
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s3 = "wdCommandDispatch" fullword ascii
      $s4 = " Type Descriptor'" fullword ascii
      $s5 = "operator<=>" fullword ascii
      $s6 = "operator co_await" fullword ascii
      $s7 = "4 4$4,4@4\\4`4|4" fullword ascii /* hex encoded string 'DDDD' */
      $s8 = ".data$rs" fullword ascii
      $s9 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s10 = " Class Hierarchy Descriptor'" fullword ascii
      $s11 = " Base Class Descriptor at (" fullword ascii
      $s12 = "wdGetApplicationObject" fullword ascii
      $s13 = " Complete Object Locator'" fullword ascii
      $s14 = "__swift_2" fullword ascii
      $s15 = "Q}vwBsuwaE" fullword ascii
      $s16 = "__swift_1" fullword ascii
      $s17 = ".rdata$voltmd" fullword ascii
      $s18 = "0'030?0K0W0" fullword ascii /* Goodware String - occured 1 times */
      $s19 = ":):L:i:" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "mO^gEN_FOlCFOdKGO}*/" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule wordLog_dat {
   meta:
      description = "MP - file wordLog.dat.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "83277bb6e77d61caa05ecfc107aa0cf5373dd72ed0c5e92dac7d027ba458b9a6"
   strings:
      $s1 = " D   gETcURRENTpROCESS rEGcREATEkEYeXw rEGdELETEvALUEw wsagETlASTeRROR " fullword ascii
      $s2 = "DLL  o$qUERYpERFORMANCEcOUNTER ;\"gETcURRENTpROCESSiD ?\"gETcURRENTtHREADiD  " fullword ascii
      $s3 = "\"gETpROCESShEAP  " fullword ascii
      $s4 = "#lOADlIBRARYeXw  A!eXITpROCESS Z\"gETmODULEhANDLEeXw  W\"gETmODULEfILEnAMEw  h#hEAPaLLOC l#hEAPfREE  X!fINDcLOSE ^!fINDfIRSTfILE" ascii
      $s5 = "#iSpROCESSORfEATUREpRESENT [\"gETmODULEhANDLEw  :\"gETcURRENTpROCESS " fullword ascii
      $s6 = "#lOADlIBRARYeXw  A!eXITpROCESS Z\"gETmODULEhANDLEeXw  W\"gETmODULEfILEnAMEw  h#hEAPaLLOC l#hEAPfREE  X!fINDcLOSE ^!fINDfIRSTfILE" ascii
      $s7 = "#lOADlIBRARYa  D\"gETlASTeRROR  *#gETtICKcOUNT  kernel" fullword ascii
      $s8 = "gETpROCESStERMINATIONmETHOD    U K         !   " fullword ascii
      $s9 = "%tERMINATEpROCESS  D$rAISEeXCEPTION  O#iNTERLOCKEDfLUSHslIST " fullword ascii
      $s10 = "!gETcOMMANDlINEw " fullword ascii
      $s11 = "\"gETsYSTEMtIMEaSfILEtIME F#iNITIALIZEslISThEAD " fullword ascii
      $s12 = "!gETcOMMANDlINEa " fullword ascii
      $s13 = "   0   aREfILEaPISansi !   0   !   0   !   0   !   0   '   0   #   0   lcmAPsTRINGeX   #   0   lOCALEnAMEtOlcid    2   aPPpOLICY" ascii
      $s14 = "dESCRIPTOR" fullword ascii
      $s15 = " D L L   cOReXITpROCESS      G" fullword ascii
      $s16 = " x   cREATEpROCESSw LSTRCPYw   c l s i d   LSTRLENw  " fullword ascii
      $s17 = "!gETcONSOLEmODE  " fullword ascii
      $s18 = "\"gETeNVIRONMENTsTRINGSw  " fullword ascii
      $s19 = "\"gETsTRINGtYPEw  q#hEAPsIZE  o#hEAPrEaLLOC n%sETsTDhANDLE  " fullword ascii
      $s20 = "\"gEToemcp  " fullword ascii
   condition:
      uint16(0) == 0x7a6d and filesize < 2000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

