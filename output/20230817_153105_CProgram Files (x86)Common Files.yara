/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule bdreinit_exe {
   meta:
      description = "MP - file bdreinit.exe.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "386eb7aa33c76ce671d6685f79512597f1fab28ea46c8ec7d89e58340081e2bd"
   strings:
      $x1 = "MiniDumpWriteDump START, ProcessID = %d, ProcessHandle = 0x%x" fullword wide
      $s2 = "CReinitProcess::GetDumpPath" fullword wide
      $s3 = "CReinitProcess::WriteDump" fullword wide
      $s4 = "d:\\Bamboo\\home\\xml-data\\build-dir\\COMMON-TRUNK-SOURCES\\bin\\Win32\\Release\\BDReinit.pdb" fullword ascii
      $s5 = "log.dll" fullword wide
      $s6 = "failed get process node" fullword wide
      $s7 = "Failed create mutex \"%s\" error ERROR_ALREADY_EXISTS" fullword wide
      $s8 = "CreateprocessAsUser() FAILED: [0x%X], [%s]" fullword wide
      $s9 = "uiscan.exe" fullword wide
      $s10 = "bdchSubmit.dll" fullword wide
      $s11 = "LoadLibrary(kernel32.dll) failed, no way to determine active session id!" fullword wide
      $s12 = "GetDumpPath failed" fullword wide
      $s13 = "cleanielow.exe" fullword wide
      $s14 = "BDReinit.exe" fullword wide
      $s15 = "Failed create mutex \"%s\" error 0x%x" fullword wide
      $s16 = "ProcessIdToSessionId failed 0x%x" fullword wide
      $s17 = "Failed create dump file" fullword wide
      $s18 = "CreateProcessAsUser() SUCCEEDED: [0x%X], [%s]" fullword wide
      $s19 = "Createprocess() FAILED: [0x%X], [%s]" fullword wide
      $s20 = "CreateProcess \"%s\" failed 0x%x" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule CProgram_Files__x86_Common_Files_log_dll {
   meta:
      description = "MP - file log.dll.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "4676eaa16c2a9684364934b314b122cdc77eb939136e2fb4ac604258ad78cc46"
   strings:
      $s1 = "Uwnq.dll" fullword ascii
      $s2 = "LogInit" fullword ascii
      $s3 = "LogFree" fullword ascii
      $s4 = "uERich1" fullword ascii
      $s5 = "6b7h7t7" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "0 0<0@0" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "2$3:3`3" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "E0_0h0" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "L$8%i}" fullword ascii
      $s10 = "9\":(:,:0:4:" fullword ascii /* Goodware String - occured 2 times */
      $s11 = ";';E;L;P;T;X;\\;`;d;h;" fullword ascii /* Goodware String - occured 2 times */
      $s12 = ":;Q;X;\\;`;d;h;l;p;t;" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "9#9+90969>9C9I9Q9V9\\9d9i9o9w9|9" fullword ascii /* Goodware String - occured 2 times */
      $s14 = ">->K>_>e>" fullword ascii /* Goodware String - occured 2 times */
      $s15 = "9,939;9@9D9H9q9" fullword ascii /* Goodware String - occured 2 times */
      $s16 = "\\$Z2L$(" fullword ascii
      $s17 = "\\$42D$" fullword ascii
      $s18 = ";*<5<P<W<\\<`<d<" fullword ascii /* Goodware String - occured 3 times */
      $s19 = "X%sS5y" fullword ascii
      $s20 = "0\"0)0u0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule info_bdreinit_exe {
   meta:
      description = "MP - file info_bdreinit.exe.txt"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "d568462a460b9297e54121a015732a49f9f2105e1a98f6ba1ad13843d9dfd66e"
   strings:
      $s1 = "C:\\Program Files (x86)\\Common Files\\bdreinit.exe: HKLM\\System\\CurrentControlSet\\Services\\BitDefender Crash Handler" fullword ascii
      $s2 = "bdreinit.exe" fullword ascii
      $s3 = "Account Owner: BUILTIN:Administrators" fullword ascii
      $s4 = "STANDARD FILE TIME:" fullword ascii
      $s5 = "FILETIME:" fullword ascii
      $s6 = "MFT Entry modified Time (MTime): 2021-11-4 7:50:32" fullword ascii
      $s7 = "File Modified Time (ATime): 2021-11-4 7:50:32" fullword ascii
      $s8 = "File Create Time (CTime): 2013-8-22 4:14:17" fullword ascii
      $s9 = "File Last Access Time (RTime): 2021-11-4 7:50:32" fullword ascii
      $s10 = "File Create Time (CTime): 2021-11-4 7:50:32" fullword ascii
      $s11 = "File Last Access Time (RTime): 2013-8-22 4:14:17" fullword ascii
      $s12 = "MFT FILE TIME:" fullword ascii
      $s13 = "File Modified Time (ATime): 2013-8-22 5:21:3" fullword ascii
      $s14 = "REGISTRY LAST WRITE TIME:" fullword ascii
      $s15 = "2022-3-8 16:42:35" fullword ascii
   condition:
      uint16(0) == 0x4946 and filesize < 2KB and
      8 of them
}

rule info_log_dat {
   meta:
      description = "MP - file info_log.dat.txt"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "58c9054bc15f29088ee073a90576f16a2f2b943460b77c6757925ebd49c3817a"
   strings:
      $s1 = "log.dat" fullword ascii
      $s2 = "Account Owner: BUILTIN:Administrators" fullword ascii
      $s3 = "STANDARD FILE TIME:" fullword ascii
      $s4 = "FILETIME:" fullword ascii
      $s5 = "MFT Entry modified Time (MTime): 2021-11-4 7:50:32" fullword ascii
      $s6 = "File Modified Time (ATime): 2021-11-4 7:50:32" fullword ascii
      $s7 = "File Create Time (CTime): 2013-8-22 4:14:17" fullword ascii
      $s8 = "File Last Access Time (RTime): 2021-11-4 7:50:32" fullword ascii
      $s9 = "File Create Time (CTime): 2021-11-4 7:50:32" fullword ascii
      $s10 = "File Last Access Time (RTime): 2013-8-22 4:14:17" fullword ascii
      $s11 = "MFT FILE TIME:" fullword ascii
      $s12 = "File Modified Time (ATime): 2013-8-22 5:21:3" fullword ascii
      $s13 = "REGISTRY LAST WRITE TIME:" fullword ascii
   condition:
      uint16(0) == 0x4946 and filesize < 1KB and
      8 of them
}

rule info_log_dll {
   meta:
      description = "MP - file info_log.dll.txt"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "2248ce7b30e53a65297c65e503a616eaa234ca6330eb6c1b817f6767c18fcef0"
   strings:
      $s1 = "log.dll" fullword ascii
      $s2 = "Account Owner: BUILTIN:Administrators" fullword ascii
      $s3 = "STANDARD FILE TIME:" fullword ascii
      $s4 = "FILETIME:" fullword ascii
      $s5 = "MFT Entry modified Time (MTime): 2021-11-4 7:50:32" fullword ascii
      $s6 = "File Modified Time (ATime): 2021-11-4 7:50:32" fullword ascii
      $s7 = "File Create Time (CTime): 2013-8-22 4:14:17" fullword ascii
      $s8 = "File Last Access Time (RTime): 2021-11-4 7:50:32" fullword ascii
      $s9 = "File Create Time (CTime): 2021-11-4 7:50:32" fullword ascii
      $s10 = "File Last Access Time (RTime): 2013-8-22 4:14:17" fullword ascii
      $s11 = "MFT FILE TIME:" fullword ascii
      $s12 = "File Modified Time (ATime): 2013-8-22 5:21:3" fullword ascii
      $s13 = "REGISTRY LAST WRITE TIME:" fullword ascii
   condition:
      uint16(0) == 0x4946 and filesize < 1KB and
      8 of them
}

rule CProgram_Files__x86_Common_Files_log_dat {
   meta:
      description = "MP - file log.dat.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "2f2b9e4a08a45cf4203c32a15684503708075d2e0b22af20d2872db2a300a768"
   strings:
      $s1 = "kiijjak" fullword ascii
      $s2 = "tjtjtjtjtjtjtjtjjpj" fullword ascii
      $s3 = "tjtjtjtjtjtj" fullword ascii
      $s4 = "zxiagzi" fullword ascii
      $s5 = "azmanjx" fullword ascii
      $s6 = "tjtjtjtjtjtjtjtj" fullword ascii
      $s7 = "dztjtjtjtjtjtjtj" fullword ascii
      $s8 = "tjtjtjtjtjtjpj" fullword ascii
      $s9 = "KfFk- Ka" fullword ascii
      $s10 = "alkowko" fullword ascii
      $s11 = "ftjtjrj" fullword ascii
      $s12 = "kkkikknkmjka" fullword ascii
      $s13 = "ktjtjtjtjtjtj" fullword ascii
      $s14 = "AIIQAAN" fullword ascii
      $s15 = "Rkmjedjmj" fullword ascii
      $s16 = "]f\\+\\.\\" fullword ascii
      $s17 = "loGo{{" fullword ascii
      $s18 = "]}\\V\\.\\&\\" fullword ascii
      $s19 = "\\ySwSHS/S>S" fullword ascii
      $s20 = "cn2F* h" fullword ascii
   condition:
      uint16(0) == 0x1f6e and filesize < 600KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _info_bdreinit_exe_info_log_dat_info_log_dll_0 {
   meta:
      description = "MP - from files info_bdreinit.exe.txt, info_log.dat.txt, info_log.dll.txt"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "d568462a460b9297e54121a015732a49f9f2105e1a98f6ba1ad13843d9dfd66e"
      hash2 = "58c9054bc15f29088ee073a90576f16a2f2b943460b77c6757925ebd49c3817a"
      hash3 = "2248ce7b30e53a65297c65e503a616eaa234ca6330eb6c1b817f6767c18fcef0"
   strings:
      $s1 = "Account Owner: BUILTIN:Administrators" fullword ascii
      $s2 = "STANDARD FILE TIME:" fullword ascii
      $s3 = "FILETIME:" fullword ascii
      $s4 = "MFT Entry modified Time (MTime): 2021-11-4 7:50:32" fullword ascii
      $s5 = "File Modified Time (ATime): 2021-11-4 7:50:32" fullword ascii
      $s6 = "File Create Time (CTime): 2013-8-22 4:14:17" fullword ascii
      $s7 = "File Last Access Time (RTime): 2021-11-4 7:50:32" fullword ascii
      $s8 = "File Create Time (CTime): 2021-11-4 7:50:32" fullword ascii
      $s9 = "File Last Access Time (RTime): 2013-8-22 4:14:17" fullword ascii
      $s10 = "MFT FILE TIME:" fullword ascii
      $s11 = "File Modified Time (ATime): 2013-8-22 5:21:3" fullword ascii
      $s12 = "REGISTRY LAST WRITE TIME:" fullword ascii
   condition:
      ( uint16(0) == 0x4946 and filesize < 2KB and ( 8 of them )
      ) or ( all of them )
}

