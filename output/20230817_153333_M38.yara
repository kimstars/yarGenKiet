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

rule M38_log {
   meta:
      description = "MP - file log.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "8d2799b016bfe40e2e3bfbd6feddd65d94f4eda249a23e7ff1e8bab017d57292"
   strings:
      $s1 = "WmQYiynPS.dll" fullword ascii
      $s2 = "LogInit" fullword ascii
      $s3 = "LogFree" fullword ascii
      $s4 = "uERich1" fullword ascii
      $s5 = "URPQQhPo" fullword ascii
      $s6 = "3$3[3s3" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "tuIb%tuIb" fullword ascii
      $s8 = "3&3+31393>3D3L3Q3W3_3d3j3r3w3}3" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "D$L2D$D" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "6)6h6}6" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "TrtZ5\\%" fullword ascii
      $s12 = "1$1(1,101<1@1D1" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "< <'<|<" fullword ascii /* Goodware String - occured 2 times */
      $s14 = "7b7h7l7p7t7" fullword ascii /* Goodware String - occured 2 times */
      $s15 = "1#1*11181?1F1N1V1^1j1s1x1~1" fullword ascii /* Goodware String - occured 2 times */
      $s16 = "5J6U6p6w6|6" fullword ascii /* Goodware String - occured 3 times */
      $s17 = "4!5G5e5l5p5t5x5|5" fullword ascii /* Goodware String - occured 3 times */
      $s18 = "D$ 2D$" fullword ascii /* Goodware String - occured 3 times */
      $s19 = "0-0:0I0S0e0t0{0" fullword ascii
      $s20 = "%B'82!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule M38_log_2 {
   meta:
      description = "MP - file log.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "74cc54e6269efc5a143776ebb9e079b8874121c356544f362e51158991dce457"
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

