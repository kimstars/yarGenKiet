/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule AdobePhotosBWg_AdobeDB {
   meta:
      description = "MP - file AdobeDB.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "b3caefb141bc47c702e71f773ed246bb9f905a222840365f2d6e432218605fd5"
   strings:
      $s1 = "0ctTavIVgaHZIkAoOZLepgctTavIVgaHZIkAoOZLepgctTavIVgaHZIkAoOZLepgctTavIVgaHZIkAoOZLepgctTavIVgaHZIkAoOZLepgctTavIVgaHZIkAoOZLepgc" ascii
      $s2 = "HZIkAoOZLepgctTavIVgaHZIkAoOJ.bpy" fullword ascii
      $s3 = "pgctUavI@gaHXIkAmOZLfpgcvTavMVgaPZIkDoOZAepgetTa" fullword ascii
      $s4 = "actTafIFgaHXIkGoOZLepgetTavIVga" fullword ascii
      $s5 = "hyqgcte" fullword ascii
      $s6 = "as{E%RoYw%llF{" fullword ascii
      $s7 = "kEYU]PhzW U" fullword ascii
      $s8 = "QDkEYw]6h" fullword ascii
      $s9 = "Pga.tFt" fullword ascii
      $s10 = "GRUn}|S]|" fullword ascii
      $s11 = "a-ZikcomZnepgAtvaTIvg" fullword ascii
      $s12 = "aqHZIkAoOZLepgctTavIVgaHZIkAoOZLepgctTavIVgaHZIkAoOZLepgctTavIVgaHZIkAoOZLepgctTavIVgaHZIkAoOZLepgctTavIVgaHZIkAoOZLepgctTavIVga" ascii
      $s13 = "Tga.tFt" fullword ascii
      $s14 = "kAkO.Ihpwct" fullword ascii
      $s15 = "cQT=vIVBa)Z%k-o:Z?e" fullword ascii
      $s16 = "^LOgeR|" fullword ascii
      $s17 = "Agcttfv" fullword ascii
      $s18 = "\\avIVgaH" fullword ascii
      $s19 = "%NFm%HZ%8F" fullword ascii
      $s20 = "\\LApgcpdFF" fullword ascii
   condition:
      uint16(0) == 0x4c5a and filesize < 1000KB and
      8 of them
}

rule AdobePhotos {
   meta:
      description = "MP - file AdobePhotos.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "6d569df32c080437ad4b144620c03883e87a7d2d3db89f752abbca7b709d5199"
   strings:
      $s1 = "c:\\ptsgsrvc\\main\\stockphotography\\launchasp\\win\\vc8\\release\\Adobe Stock Photos CS3.pdb" fullword ascii
      $s2 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC80.CRT\" version=\"8.0.50608.0\" processorArchitecture=\"x86\" publicK" ascii
      $s3 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC80.CRT\" version=\"8.0.50608.0\" processorArchitecture=\"x86\" publicK" ascii
      $s4 = " Processed" fullword ascii
      $s5 = "PostScript, PDF" fullword wide
      $s6 = "http://www.adobe.com0" fullword ascii
      $s7 = " http://crl.verisign.com/pca3.crl0" fullword ascii
      $s8 = "Custom Headers:" fullword ascii
      $s9 = "/headers;Headers;(no headers);" fullword ascii
      $s10 = "Header_" fullword ascii
      $s11 = "lttttttmiiiiiiij" fullword ascii
      $s12 = "kiiiiiiiiij" fullword ascii
      $s13 = " -nostartupscreen" fullword ascii
      $s14 = "kiiiiiij" fullword ascii
      $s15 = " -instance " fullword ascii
      $s16 = "jiiiiiiiiij" fullword ascii
      $s17 = "kiiiiiiij" fullword ascii
      $s18 = "Adobe Systems Incorporated1>0<" fullword ascii
      $s19 = "?</Configuration>" fullword ascii
      $s20 = "pcdOpenSession" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule Adobe_Caps {
   meta:
      description = "MP - file Adobe_Caps.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "39945063c73af8263b58f7ab899afb575486c1a49af0ca465e54f84c6b2d1df4"
   strings:
      $s1 = "lJCIaRPDwJJ.dll" fullword ascii
      $s2 = "bedb.dat" fullword ascii
      $s3 = " Type Descriptor'" fullword ascii
      $s4 = "fdlvowelyqonqwbbcjiseqvjvxhtwulbmfpigb" fullword ascii
      $s5 = "rxlshatqkxmixuhopextccjycgmuaynckjaeerblxncm" fullword ascii
      $s6 = "davhtexsxmlf" fullword ascii
      $s7 = "pcdOpenSession" fullword ascii
      $s8 = " Class Hierarchy Descriptor'" fullword ascii
      $s9 = " Base Class Descriptor at (" fullword ascii
      $s10 = " Complete Object Locator'" fullword ascii
      $s11 = "1$1@1a1" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "8D8T8d8t8" fullword ascii /* Goodware String - occured 1 times */
      $s13 = ":';2;8;" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "=\"=)=u=" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "5!5+5;5" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "3#3:3X3" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "60686L6h6" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "5!6G6e6l6p6t6x6|6" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "00I0O0" fullword ascii /* Goodware String - occured 1 times */
      $s20 = " delete[]" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

