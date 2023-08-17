/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule bdreinit {
   meta:
      description = "MP - file bdreinit.exe"
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

rule ARO_2012_log {
   meta:
      description = "MP - file log.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "4488cd155c6da33799ad5ffd93b074d04f86ab3744f03015567f0711701e1a7a"
   strings:
      $s1 = "ZhhOpGRHd.dll" fullword ascii
      $s2 = "LogInit" fullword ascii
      $s3 = "Kkernel32" fullword ascii
      $s4 = "LogFree" fullword ascii
      $s5 = "uERich1" fullword ascii
      $s6 = "=%>?>H>j>" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "2'3-33393?3E3L3S3Z3a3h3o3v3~3" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "1$1(1,101<1@1D1" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "<+<?<E<" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "L$ 2L$(" fullword ascii /* Goodware String - occured 1 times */
      $s11 = ":0:7:<:@:D:e:" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "0C0H0R0" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "77$7*72777=7E7J7P7X7]7c7k7p7v7~7" fullword ascii /* Goodware String - occured 2 times */
      $s14 = "81989<9@9D9H9L9P9T9" fullword ascii /* Goodware String - occured 2 times */
      $s15 = "6B6T6f6x6" fullword ascii /* Goodware String - occured 2 times */
      $s16 = "7 7$7(7Q7w7" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "999L9\\9" fullword ascii /* Goodware String - occured 3 times */
      $s18 = "\\$< d$<0" fullword ascii
      $s19 = ":#:::X:" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "0!010c0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule ARO_2012_log_2 {
   meta:
      description = "MP - file log.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "e8fb9d757c918622e2fd6a39b86e3c407da413dc50250c5c768b17fe61ecc7fc"
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
      $s15 = "MMMMMMMMMMMMMMMMMMMM" fullword ascii
      $s16 = "Rkmjedjmj" fullword ascii
      $s17 = "]f\\+\\.\\" fullword ascii
      $s18 = "loGo{{" fullword ascii
      $s19 = "]}\\V\\.\\&\\" fullword ascii
      $s20 = "\\ySwSHS/S>S" fullword ascii
   condition:
      uint16(0) == 0x1f6e and filesize < 600KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

