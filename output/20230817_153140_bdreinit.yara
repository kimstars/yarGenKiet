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

rule bdreinit_log {
   meta:
      description = "MP - file log.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "44c4e1ef6b7a22477310276bdb85ce260bf3bd9cccf781be8846afa6fc5e4ee2"
   strings:
      $s1 = "tAthlBnm.dll" fullword ascii
      $s2 = "LogInit" fullword ascii
      $s3 = "LogFree" fullword ascii
      $s4 = "@s%m%9" fullword ascii
      $s5 = "uERich1" fullword ascii
      $s6 = ":&;+;=;[;o;u;\"<'<,<C<" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "5#5)51565<5D5I5O5W5\\5b5j5o5u5}5" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "s*\\-%s*\\-" fullword ascii
      $s9 = "3#4K4Y4" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "1$1(1,101<1@1D1" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "S!Q6%i?2" fullword ascii
      $s12 = "303>3D3" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "8K9S9j9" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "]~hPq{UMGeMICiID?oypn:|UOS" fullword ascii
      $s15 = "?#?)?/?" fullword ascii /* Goodware String - occured 2 times */
      $s16 = ">C?M?h?r?" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "97:@:h:" fullword ascii /* Goodware String - occured 2 times */
      $s18 = "=^>f>r>" fullword ascii /* Goodware String - occured 2 times */
      $s19 = "\\U{I5H" fullword ascii
      $s20 = "8/8a8h8l8p8t8x8|8" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule bdreinit_log_2 {
   meta:
      description = "MP - file log.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "2de77804e2bd9b843a826f194389c2605cfc17fd2fafde1b8eb2f819fc6c0c84"
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

