/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule MPv18_log_dat {
   meta:
      description = "MP - file log.dat.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "3f7b7664c681aa9568082ceb0f403aeaf24d242c147a04ebcecfedf62efa65bd"
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

rule MPv18_log_dll {
   meta:
      description = "MP - file log.dll.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "0f470dd62707fc875288c4cfea9553f9cdb489dd09a4badb3302a64f9211ae06"
   strings:
      $s1 = "OyM.dll" fullword ascii
      $s2 = "LogInit" fullword ascii
      $s3 = "LogFree" fullword ascii
      $s4 = "5Mf~d $ !*-kernel32" fullword ascii
      $s5 = "LiyC`td~vR|zrVxw.xhc" fullword ascii
      $s6 = "8P9r:z:\"<" fullword ascii
      $s7 = "uERich1" fullword ascii
      $s8 = "7*858P8W8\\8`8d8" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "4!4b4t4" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "1$1(1,101<1@1D1" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "7'7E7L7P7T7X7\\7`7d7h7" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "XEyC%XEyC" fullword ascii
      $s13 = "?&?O?j?" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "5\"6(6,60646" fullword ascii /* Goodware String - occured 2 times */
      $s15 = ":-:K:_:e:" fullword ascii /* Goodware String - occured 3 times */
      $s16 = ";E<_<h<" fullword ascii /* Goodware String - occured 3 times */
      $s17 = "6'6<6X6y6" fullword ascii
      $s18 = "3,313@3n3" fullword ascii
      $s19 = "5#5+50565>5C5I5Q5V5\\5d5i5o5w5|5" fullword ascii
      $s20 = "8/8@8L8S8Z8u8" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

