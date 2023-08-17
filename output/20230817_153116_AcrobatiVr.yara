/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule AcrobatiVr_Acrobat {
   meta:
      description = "MP - file Acrobat.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "0459e62c5444896d5be404c559c834ba455fa5cae1689c70fc8c61bc15468681"
   strings:
      $x1 = "C:\\builds\\ACC\\GM\\source\\dev\\target\\win32\\Release\\HEX\\Adobe CEF Helper.pdb" fullword ascii
      $s2 = "HEX.dll" fullword wide
      $s3 = "Adobe CEF Helper.exe" fullword wide
      $s4 = "CEFProcessForkHandlerEx" fullword ascii
      $s5 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s6 = "http://sw1.symcb.com/sw.crt0" fullword ascii
      $s7 = "http://sw.symcb.com/sw.crl0" fullword ascii
      $s8 = " Type Descriptor'" fullword ascii
      $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s10 = "Adobe Systems Incorporated1" fullword ascii
      $s11 = "Adobe Systems Incorporated0" fullword ascii
      $s12 = "Aapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
      $s13 = "nFailed to remove file spec error: %d" fullword wide
      $s14 = "Copyright 2013-2016 Adobe Systems Incorporated. All rights reserved." fullword wide
      $s15 = "b<log10" fullword ascii
      $s16 = " Base Class Descriptor at (" fullword ascii
      $s17 = " Class Hierarchy Descriptor'" fullword ascii
      $s18 = " Complete Object Locator'" fullword ascii
      $s19 = "Aadvapi32" fullword wide
      $s20 = "owner dead" fullword ascii /* Goodware String - occured 567 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule AcrobatiVr_hex {
   meta:
      description = "MP - file hex.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "5928048ed1d76df1ae4f3ede0e3da0b0006734f712a78036e6f4b6a78c05f0c6"
   strings:
      $s1 = "hex.dll" fullword ascii
      $s2 = "CEFProcessForkHandlerEx" fullword ascii
      $s3 = "6#6*6/6@6\\6" fullword ascii /* hex encoded string 'fff' */
      $s4 = "lbuyvmprwrwldlahoirfacnxrjqkuiug" fullword ascii
      $s5 = "upllrjlxcusodtcyuigdognlnvrqlfrgfvykwdir" fullword ascii
      $s6 = "lwsyemdbtehynlcyep" fullword ascii
      $s7 = "wiesgtbdntaxjpyculrwukntmurg" fullword ascii
      $s8 = "pkurkqelxhbnovenljwiusuodtapmxclimyoghywfdfdwkyo" fullword ascii
      $s9 = "gkpfevbrbfjbwgmpcyhmlijkrovrbxsdg" fullword ascii
      $s10 = "7*858P8W8\\8`8d8" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "^}%95|" fullword ascii /* Goodware String - occured 2 times */
      $s12 = "0-14181<1@1D1H1L1P1" fullword ascii /* Goodware String - occured 3 times */
      $s13 = ";&;/;;;m;" fullword ascii
      $s14 = "0-151^1k1p1}1" fullword ascii
      $s15 = "?,?3?E?M?]?n?" fullword ascii
      $s16 = "969C9H9l9" fullword ascii
      $s17 = "7+7E7L7P7T7X7\\7`7d7h7" fullword ascii
      $s18 = "2Q2s2{2" fullword ascii
      $s19 = "=7===I=Y=`=g=m=" fullword ascii
      $s20 = "0!0@0[0c0i0o0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule AvastSvc {
   meta:
      description = "MP - file AvastSvc.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "85ca20eeec3400c68a62639a01928a5dab824d2eadf589e5cbfe5a2bc41d9654"
   strings:
      $s1 = "d:\\Workspace\\workspace\\ProductionClients-ForRelease\\AVBranding\\avast\\CONFIG\\Release\\label_exp\\WinClient\\BUILDS\\Releas" ascii
      $s2 = "wsc_proxy.exe" fullword wide
      $s3 = "wsc.dll" fullword wide
      $s4 = "d:\\Workspace\\workspace\\ProductionClients-ForRelease\\AVBranding\\avast\\CONFIG\\Release\\label_exp\\WinClient\\BUILDS\\Releas" ascii
      $s5 = "roxy.pdb" fullword ascii
      $s6 = "http://www.avast.com0/" fullword ascii
      $s7 = "http://www.avast.com0" fullword ascii
      $s8 = "AVAST Software" fullword wide
      $s9 = " Microsoft Code Verification Root0" fullword ascii
      $s10 = "'FFFFFFFB" fullword ascii
      $s11 = "@FFFFFFFF7FFF" fullword ascii
      $s12 = "FFFFFFFF7FFF" ascii
      $s13 = "FFFF=14CFCFFF" fullword ascii
      $s14 = "_run@4" fullword ascii
      $s15 = "Praha 41" fullword ascii
      $s16 = "<FFFFFF3" fullword ascii
      $s17 = " HGDEQc7" fullword ascii
      $s18 = " 0xAbMk^n" fullword ascii
      $s19 = "AVAST Software s.r.o.1" fullword ascii
      $s20 = "AVAST Software s.r.o.0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule adobeupdate {
   meta:
      description = "MP - file adobeupdate.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "d1f848a8477f171430b339acc4d0113660907705d85fa8ea4fbd9bf4ae20a116"
   strings:
      $s1 = "4bxbtucGeLnbxbtucGeLnbxbtucGeLnbxbtucGeLnbxbtucGeLnbxbtucGeLnbxbtucGeLnbxbtucGeLnbxbtucGeLnbxbtucGeLnbxbtucGeLnbxbtucGeLnbxbtucG" ascii
      $s2 = "\\}\\QLWBB[~TLnbxbtucGeLncxbtccGeNnbx`tucDeLn`xbtqcGeTnbxgtucJeLndxbt|cGeKnbxntucOeLnnxbt|cGe@nbxhtuc@eLnixbt}cGe@nbxttucJeLntxb" ascii
      $s3 = "\\}\\QLWBB[~TLnbxbtucGeLncxbtccGeNnbx`tucDeLn`xbtqcGeTnbxgtucJeLndxbt|cGeKnbxntucOeLnnxbt|cGe@nbxhtuc@eLnixbt}cGe@nbxttucJeLntxb" ascii
      $s4 = "9EuFfbxb/wsKmLnn#`dekGeT5`hq|ucc>N~vpbtE8EuZfbx^/ws]mLn*#`dhkGe,5`hN|uc+>N~Ypbt" fullword ascii
      $s5 = "eLnr/`d;cGeT9`h-tucg2N~2xbt]4Eu" fullword ascii
      $s6 = "obxbtuc" fullword ascii
      $s7 = "nbxstuc" fullword ascii
      $s8 = "nbxhtuc" fullword ascii
      $s9 = "Imrxbtu" fullword ascii
      $s10 = "Dnbxbtuc" fullword ascii
      $s11 = "xbtuc e nbxbt" fullword ascii
      $s12 = "\\}\\QLWBB[~T~]VMTCMZvW" fullword ascii
      $s13 = "ybtuct" fullword ascii
      $s14 = "Lnbxbt4" fullword ascii
      $s15 = "boxjtu" fullword ascii
      $s16 = "\\GuMnRxbtVS1Uc_" fullword ascii
      $s17 = "\\lbxctuc" fullword ascii
      $s18 = "chbtuc" fullword ascii
      $s19 = "gubduc" fullword ascii
      $s20 = "gtobxb" fullword ascii
   condition:
      uint16(0) == 0x7862 and filesize < 500KB and
      8 of them
}

rule AvastAuth {
   meta:
      description = "MP - file AvastAuth.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "24437d65bee4874fba99a2d57bf050ba719a69518160cebafbd8f7441368093a"
   strings:
      $s1 = "5=vJLvnTAFax:\"7#+" fullword ascii
      $s2 = "PMAIrCT" fullword ascii
      $s3 = "DIEERKrfnHNCKKXAdptRP]QQNWnzz\\ZWggtmPD@flammzcZNVpv{ss`yLX\\zxuyy" fullword ascii
      $s4 = "gFV.Nta" fullword ascii
      $s5 = "gAb.FFl(ua('EH" fullword ascii
      $s6 = "eBQeIW.Zouq" fullword ascii
      $s7 = "ADHMFVN" fullword ascii
      $s8 = "WFXEFVN" fullword ascii
      $s9 = "ADHEFVN" fullword ascii
      $s10 = "OCTMGNVNO" fullword ascii
      $s11 = "GADHGFVN" fullword ascii
      $s12 = "ADHJFVN" fullword ascii
      $s13 = "A%H%F:N" fullword ascii
      $s14 = "\\VMFXG2S" fullword ascii
      $s15 = "\" -!!>'" fullword ascii
      $s16 = "a -1;/" fullword ascii
      $s17 = ".+3<ta1 -<" fullword ascii
      $s18 = "/'$Ned1( -" fullword ascii
      $s19 = "DHGFVN5" fullword ascii
      $s20 = "ADH%F%NYa" fullword ascii
   condition:
      uint16(0) == 0x4844 and filesize < 300KB and
      8 of them
}

rule AvastGuide {
   meta:
      description = "MP - file AvastGuide.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "acfd58369c0a7dbc866ad4ca9cb0fe69d017587af88297f1eaf62a9a8b1b74b4"
   strings:
      $s1 = "3DHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNt" ascii
      $s2 = "1ADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVN" ascii
      $s3 = "6 6)*#\"+" fullword ascii /* hex encoded string 'f' */
      $s4 = "56!%3\"+,|&A" fullword ascii /* hex encoded string 'V:' */
      $s5 = "%6-452^4a" fullword ascii /* hex encoded string 'dRJ' */
      $s6 = "=;3#;`&5*" fullword ascii /* hex encoded string '5' */
      $s7 = "37!((VNta4 -;\"" fullword ascii
      $s8 = "D\\GFVN~'1 -<" fullword ascii
      $s9 = "'ADHGFTN~$+ 0 " fullword ascii
      $s10 = ")5%pafADHGFVOtaf%T" fullword ascii
      $s11 = "-+ TNuafADIG@" fullword ascii
      $s12 = "pwPUztWG_@pSwsp~|G_epwPUYVWG_epwPUYVWG_epwPUYVWG_epwPUYVWG_eZZ}xt{zjrI\\[|yuz{ksI\\[|yuz{ksI\\[|yYyyG" fullword ascii
      $s13 = "[_TZXInUCEean`nwg^JJljgwaG_epwPUYVWG_epwPUYVWG_epwpUYVWG_epwPUYVWG_epwPUYVWG_epwPUYVWG_epwPUYVWG_epwPUYVWG_epwPUYVWG_epwPUYVWG_e" ascii
      $s14 = "VNte5$(.EFT" fullword ascii
      $s15 = "dADHwF.NtafA" fullword ascii
      $s16 = "DHGGTMpd`FLAMMZCznvPV[SWCXcy" fullword ascii
      $s17 = "FRRNq~pDTMpd`FLAMTnwUr\\UPsaFVIU][@DHGFVNvbbDBOOO\\\\LXX~" fullword ascii
      $s18 = "VNte5$(.EFV*d!f@DL" fullword ascii
      $s19 = "VNte5$(.EFV*d!f@DO" fullword ascii
      $s20 = "!fCEHEDTMpdfCFN" fullword ascii
   condition:
      uint16(0) == 0x4844 and filesize < 500KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _AvastAuth_AvastGuide_0 {
   meta:
      description = "MP - from files AvastAuth.dat, AvastGuide.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "24437d65bee4874fba99a2d57bf050ba719a69518160cebafbd8f7441368093a"
      hash2 = "acfd58369c0a7dbc866ad4ca9cb0fe69d017587af88297f1eaf62a9a8b1b74b4"
   strings:
      $s1 = "VNtafADH" fullword ascii
      $s2 = "DHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNta" ascii
      $s3 = "DHGFVNtafA" fullword ascii
      $s4 = "NtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHGFVNtafADHG" ascii
      $s5 = "aFADHGF" fullword ascii
      $s6 = "tafADHGF" fullword ascii
      $s7 = "A!HGFVN" fullword ascii
      $s8 = "A*H FvN" fullword ascii
      $s9 = "AdH\"F8N" fullword ascii
      $s10 = "A%H$F3NTa" fullword ascii
      $s11 = "A%H+F?N" fullword ascii
      $s12 = "1423#8" fullword ascii
      $s13 = "A(H&F\"N" fullword ascii
      $s14 = "p4y3w." fullword ascii
      $s15 = "tafADH" fullword ascii
      $s16 = "AdH&FvN" fullword ascii
      $s17 = "A+H)FvN" fullword ascii
      $s18 = "A6HgF%N" fullword ascii
      $s19 = "AdH(F$NTa" fullword ascii
      $s20 = "A-H3F?N" fullword ascii
   condition:
      ( uint16(0) == 0x4844 and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

