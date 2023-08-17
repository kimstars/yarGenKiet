/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule ARO_2012_log {
   meta:
      description = "MP - file log.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "3268dc1cd5c629209df16b120e22f601a7642a85628b82c4715fe2b9fbc19eb0"
   strings:
      $s1 = "::::::::::::::::::::::::::::::::::::::::::::3333" fullword ascii /* hex encoded string '33' */
      $s2 = "kiijjak" fullword ascii
      $s3 = "tjtjtjtjtjtjtjtjjpj" fullword ascii
      $s4 = "tjtjtjtjtjtj" fullword ascii
      $s5 = "zxiagzi" fullword ascii
      $s6 = "azmanjx" fullword ascii
      $s7 = "tjtjtjtjtjtjtjtj" fullword ascii
      $s8 = "dztjtjtjtjtjtjtj" fullword ascii
      $s9 = "tjtjtjtjtjtjpj" fullword ascii
      $s10 = "KfFk- Ka" fullword ascii
      $s11 = "alkowko" fullword ascii
      $s12 = "ftjtjrj" fullword ascii
      $s13 = "kkkikknkmjka" fullword ascii
      $s14 = "ktjtjtjtjtjtj" fullword ascii
      $s15 = "AIIQAAN" fullword ascii
      $s16 = "Rkmjedjmj" fullword ascii
      $s17 = "]f\\+\\.\\" fullword ascii
      $s18 = "loGo{{" fullword ascii
      $s19 = "]}\\V\\.\\&\\" fullword ascii
      $s20 = "\\ySwSHS/S>S" fullword ascii
   condition:
      uint16(0) == 0x1f6e and filesize < 600KB and
      8 of them
}

rule ARO_2012_log_2 {
   meta:
      description = "MP - file log.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "db0c90da56ad338fa48c720d001f8ed240d545b032b2c2135b87eb9a56b07721"
   strings:
      $s1 = "dqd.dll" fullword ascii
      $s2 = "LogInit" fullword ascii
      $s3 = "LogFree" fullword ascii
      $s4 = ">#>->3>9>?>" fullword ascii /* hex encoded string '9' */
      $s5 = "uERich1" fullword ascii
      $s6 = "0 0<0@0" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "5%5*50585=5C5K5P5V5^5c5i5q5v5|5" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "< <B<I<" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "8 8&848:8O8`8l8s8z8" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "=#=(=1=" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "6!7G7e7l7p7t7x7|7" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "96:;:M:k:" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "1$1.1T1" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "0@0]0{0" fullword ascii /* Goodware String - occured 2 times */
      $s15 = "5B6H6L6P6T6" fullword ascii /* Goodware String - occured 2 times */
      $s16 = "7J8U8p8w8|8" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "8G9P9x9" fullword ascii /* Goodware String - occured 2 times */
      $s18 = "\\$  |$" fullword ascii
      $s19 = "\\$00l$" fullword ascii
      $s20 = "\\$ !T$ 1" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

