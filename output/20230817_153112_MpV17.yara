/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule MpV17_log_dat {
   meta:
      description = "MP - file log.dat.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "0e9e270244371a51fbb0991ee246ef34775787132822d85da0c99f10b17539c0"
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

rule MpV17_log_dll {
   meta:
      description = "MP - file log.dll.sc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "3171285c4a846368937968bf53bc48ae5c980fe32b0de10cf0226b9122576f4e"
   strings:
      $s1 = "ljAt.dll" fullword ascii
      $s2 = "LogInit" fullword ascii
      $s3 = "LogFree" fullword ascii
      $s4 = "O-%H%O-%H" fullword ascii
      $s5 = "uERich1" fullword ascii
      $s6 = "0K1S1j1" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "6!6t6y6" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "7#7)7/7" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "1$1(1,101<1@1D1" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "070U0\\0`0d0h0l0p0t0x0" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "=#=)=1=6=<=D=I=O=W=\\=b=j=o=u=}=" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "131L1w1" fullword ascii /* Goodware String - occured 1 times */
      $s13 = ">5nmCM!" fullword ascii
      $s14 = "::W:]:c:i:o:u:|:" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "0:1E1`1g1l1p1t1" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "4U5o5x5" fullword ascii /* Goodware String - occured 2 times */
      $s17 = ";<;P;[;l;r;" fullword ascii
      $s18 = "5F7Q7a7" fullword ascii
      $s19 = "676A6G6[6g6" fullword ascii
      $s20 = "5%5*5V5\\5b5s5" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

