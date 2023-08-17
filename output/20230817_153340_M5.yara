/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule M5_1 {
   meta:
      description = "MP - file 1.bat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "87a9a800cd57bf7592b5c4d08ba9cb5e96dc4e7f8eb1badc2385407fddbf556e"
   strings:
      $x1 = "start /b %temp%\\2.exe E:\\Data\\ %~dp0" fullword ascii
      $x2 = "copy /y %~dp02.exe %temp%\\2.exe" fullword ascii
   condition:
      uint16(0) == 0x6f63 and filesize < 1KB and
      1 of ($x*)
}

rule M5_1_2 {
   meta:
      description = "MP - file 1.exe"
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

rule M5_2 {
   meta:
      description = "MP - file 2.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "906068fdc794387b855a5d8284eac0df905db8625b1ba4b34dd679a9400460c8"
   strings:
      $s1 = " http://www.microsoft.com/windows0" fullword ascii
      $s2 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s3 = ":':?:J:\\:g:y:" fullword ascii
      $s4 = "7@:D:H:L:P:T:X:\\:`:d:p:x:" fullword ascii
      $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s6 = "8]8h8n8" fullword ascii /* Goodware String - occured 1 times */
      $s7 = ":$;C;x;" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "0=0f0y0" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "3l<t<|<" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "  </trustInfo>" fullword ascii
      $s11 = "AdobeDB." fullword wide
      $s12 = "=O=U=a=" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "9 9'9,90949U9" fullword ascii /* Goodware String - occured 2 times */
      $s14 = "G;|$ u" fullword ascii /* Goodware String - occured 2 times */
      $s15 = "819;9V9" fullword ascii /* Goodware String - occured 2 times */
      $s16 = "313W3u3|3" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "%temp%\\" fullword wide /* Goodware String - occured 2 times */
      $s18 = "      </requestedPrivileges>" fullword ascii
      $s19 = "= =$=0=4=8=<=@=D=H=L=T=X=p=" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "      <requestedPrivileges>" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule Adobe_Caps {
   meta:
      description = "MP - file Adobe_Caps.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "5b9dc9b6bd1d582e0613d25353679df894b1f65d0b9ac3827ace3fc40edb9c2d"
   strings:
      $s1 = "oWPZvANrQwR.dll" fullword ascii
      $s2 = " Type Descriptor'" fullword ascii
      $s3 = "4)4.4:4?4^4" fullword ascii /* hex encoded string 'DDD' */
      $s4 = "wgasrrmqjfdkyttvoaymvinbpqbykaovvmouw" fullword ascii
      $s5 = "pgctmdwcctrgwqtbmajvaqfvgmftnur" fullword ascii
      $s6 = "pcdOpenSession" fullword ascii
      $s7 = " Class Hierarchy Descriptor'" fullword ascii
      $s8 = " Base Class Descriptor at (" fullword ascii
      $s9 = " Complete Object Locator'" fullword ascii
      $s10 = "gxcurk" fullword ascii
      $s11 = "3&3+31393>3D3L3Q3W3_3d3j3r3w3}3" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "505@5D5X5\\5l5p5t5|5" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "2 2$2E2o2" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "2B3H3L3P3T3" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "E0c0|0" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "424R4x4" fullword ascii /* Goodware String - occured 1 times */
      $s17 = " delete[]" fullword ascii
      $s18 = " delete" fullword ascii
      $s19 = "8 8(8<8X8x8" fullword ascii /* Goodware String - occured 2 times */
      $s20 = "= =$=(=,=8=<=@=D=H=L=P=T=\\=`=" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule M5_AdobeDB {
   meta:
      description = "MP - file AdobeDB.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "648057cdf0c5743b8ef143923c5dbab8f81d3f8b4b0aa6a6ca4561f25654c081"
   strings:
      $s1 = "@`bJEtd:\\'^D|aG6{p" fullword ascii
      $s2 = "hLjHI.rYD" fullword ascii
      $s3 = "P>YhLOg*M" fullword ascii
      $s4 = "YhLOg>M" fullword ascii
      $s5 = "veSPYEB" fullword ascii
      $s6 = "DpDVbdR_PbY0LOg{M\\yvp" fullword ascii
      $s7 = "PjYHLOg:Mry" fullword ascii
      $s8 = "v}SPYE^a-" fullword ascii
      $s9 = "xmwitui" fullword ascii
      $s10 = "TJ:\"IM" fullword ascii
      $s11 = "5VRq:\\" fullword ascii
      $s12 = "SPYE99" fullword ascii
      $s13 = "v:\"IM}=" fullword ascii
      $s14 = "TD:\"IM" fullword ascii
      $s15 = "V7q3P|hLjHI.rYD" fullword ascii
      $s16 = "o+fhLj'MM.yDp" fullword ascii
      $s17 = "TK:\"IM" fullword ascii
      $s18 = "vTu.yeF" fullword ascii
      $s19 = "v]SPYE" fullword ascii
      $s20 = "vaSPYh" fullword ascii
   condition:
      uint16(0) == 0x724d and filesize < 1000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

