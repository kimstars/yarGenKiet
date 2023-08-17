/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule md_AdobeDB {
   meta:
      description = "MP - file AdobeDB.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "d9d730997eaa88740e4991bb175cb3e66dca4cfb3a0fc0308527966e777920cb"
   strings:
      $s1 = "\"7==25 -0+\"" fullword ascii /* hex encoded string 'rP' */
      $s2 = "jgZMNP.PbH" fullword ascii
      $s3 = "FYGoABfU.UeX" fullword ascii
      $s4 = "JRfEnEeHHrCd{SDYO@vTJrXFnKCgToTdYIrCd{SDYO@vTJrXFnKCgToEeYIrCd{SDYO@vTJqXEnHCdTlTgYJr@dxSGYL@uTIr[FmK@gWoWdZIqCg{PDZOCvEKqXEnHCd" ascii
      $s5 = "O@vTJrXFnKCgToTdYIrCd{SDYO@vTJrXFnKCgToTdHHcBuzBEHNQw" fullword ascii
      $s6 = "* *;+2" fullword ascii
      $s7 = "JRfEnEeHHrCd{SDYO@vTJrXFnKCgToTdYIrCd{SDYO@vTJrXFnKCgToEeYIrCd{SDYO@vTJqXEnHCdTlTgYJr@dxSGYL@uTIr[FmK@gWoWdZIqCg{PDZOCvEKqXEnHCd" ascii
      $s8 = "E6N.wUKsY4o'B" fullword ascii
      $s9 = "E6N.wUK" fullword ascii
      $s10 = "fJfU.jbHs{Be\"mBHpIwU/L^W,BBf%QRu3@sB" fullword ascii
      $s11 = "BinUeXy" fullword ascii
      $s12 = "nNrUnUeXH" fullword ascii
      $s13 = "AwUkH^W.JBf" fullword ascii
      $s14 = "NAwUK|FG*q.BEa" fullword ascii
      $s15 = "nfrUnUeXH" fullword ascii
      $s16 = "KEYwo{BQUcUoXesbe" fullword ascii
      $s17 = "VMRrUnU" fullword ascii
      $s18 = "hZCrUn-%_XwVez" fullword ascii
      $s19 = "nFrUnUeXH" fullword ascii
      $s20 = "APPEXNA" fullword ascii
   condition:
      uint16(0) == 0x5973 and filesize < 1000KB and
      8 of them
}

rule AdobePhoto {
   meta:
      description = "MP - file AdobePhoto.exe"
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
      hash1 = "550348eae900a5cd03dddacf060a22bb121bb7bc65ed7801234fd614133c3195"
   strings:
      $s1 = "oiUScWoVneQ.dll" fullword ascii
      $s2 = " Type Descriptor'" fullword ascii
      $s3 = "2 2&2+272" fullword ascii /* hex encoded string '""r' */
      $s4 = "ulhugngodfblvvwmjgrjhxjurpjddlkwxuiglrmi" fullword ascii
      $s5 = "diypmyuockfdqyshuwyfhtjikivgjxnk" fullword ascii
      $s6 = "jphjgpvgsmrqqwhorseupxrw" fullword ascii
      $s7 = "xtdiiryxyjv" fullword ascii
      $s8 = "eyhalrfskfjyfbmolknwpasqywrtuhqpro" fullword ascii
      $s9 = "pcdOpenSession" fullword ascii
      $s10 = " Class Hierarchy Descriptor'" fullword ascii
      $s11 = " Base Class Descriptor at (" fullword ascii
      $s12 = " Complete Object Locator'" fullword ascii
      $s13 = "6C7k7y7%9C9\\9c9k9p9t9x9" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "0,131;1" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "869<9v9|9" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "88&8>8M8W8d8n8~8" fullword ascii /* Goodware String - occured 1 times */
      $s17 = ">&>2>A>" fullword ascii /* Goodware String - occured 1 times */
      $s18 = ":#:(:.:6:;:A:I:N:T:\\:a:g:o:t:z:" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "> ?4?d?" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "?#?0?X?" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

