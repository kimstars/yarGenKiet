/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule M4_1 {
   meta:
      description = "MP - file 1.bat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "fdd12fbf51699d06d84d5a85e72d9e6951d3df8d62ad37b3a611ba885d6d6381"
   strings:
      $x1 = "start /b %temp%\\1.exe F:\\Data\\ %~dp0" fullword ascii
      $x2 = "copy /y %~dp0Adobe_Caps.dll %temp%\\Adobe_Caps.dll" fullword ascii
      $x3 = "copy /y %~dp01.exe %temp%\\1.exe" fullword ascii
      $s4 = "copy /y %~dp0AdobeDB.dat %temp%\\AdobeDB.dat" fullword ascii
   condition:
      uint16(0) == 0x6f63 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule M4_1_2 {
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

rule Adobe_Caps {
   meta:
      description = "MP - file Adobe_Caps.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "15e66ea8656a4cadd0b62eaf8c8e5c3492e4640c89bcd93adb96d5c6dcf56f8b"
   strings:
      $s1 = "nTBDEGCmfxu.dll" fullword ascii
      $s2 = "bedb.dat" fullword ascii
      $s3 = " Type Descriptor'" fullword ascii
      $s4 = "ngqwcjuwlrthhhmcbdiysggehomufdumip" fullword ascii
      $s5 = "ifhovvtoxyjlcxrogwf" fullword ascii
      $s6 = "qavyqfyfut" fullword ascii
      $s7 = "auyalisciljlawullxrxlafxogtcfglyrhbemnqxntkjhndhw" fullword ascii
      $s8 = "eufihxkxpwjvqhuitiljfyliiwsxrm" fullword ascii
      $s9 = "smuyesjruxwhwapfafak" fullword ascii
      $s10 = "sokndmiiofxxnjwmwosfu" fullword ascii
      $s11 = "njinxnpyuawcsyegxveskenfsb" fullword ascii
      $s12 = "pcdOpenSession" fullword ascii
      $s13 = "9E:K:\";(;" fullword ascii
      $s14 = " Class Hierarchy Descriptor'" fullword ascii
      $s15 = " Base Class Descriptor at (" fullword ascii
      $s16 = " Complete Object Locator'" fullword ascii
      $s17 = "8D8T8d8t8" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "=H=M=W=" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "4&4+41494>4D4L4Q4W4_4d4j4r4w4}4" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "1:1`1t1" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule M4_AdobeDB {
   meta:
      description = "MP - file AdobeDB.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "041bb1a27f4f6e8a95530f63092ca64d515e4e37eb916fb3571a524c896e856f"
   strings:
      $s1 = "cQGBrgsSuaMHhb3Fx+dQGBrgsSuaMHhbsFxidQGBrgsSuaMHhbsFxidQGBrgsSuaMHhbsFxidQGBrgsSuaMHhbsFxidQGBrgsSuaMHhbsFxidQGBrgsSuaMHhbsFxidQ" ascii
      $s2 = "6CcSuaM.Fml" fullword ascii
      $s3 = "iTzbs.yid" fullword ascii
      $s4 = "grfzrnt" fullword ascii
      $s5 = "2W\\WfiqDgVk[Y5H8- " fullword ascii
      $s6 = "grvtgnt" fullword ascii
      $s7 = "H4b]F$idQvB.gsS)a=H4bsF]i7QGBWg" fullword ascii
      $s8 = "9Ea.Fml" fullword ascii
      $s9 = "Q4B.gsS" fullword ascii
      $s10 = "Pa.HRb/FxiKQ$BRg" fullword ascii
      $s11 = "saM.Fml" fullword ascii
      $s12 = "v:\\+x$W" fullword ascii
      $s13 = "G0pM.Fml" fullword ascii
      $s14 = "vaM.Fml" fullword ascii
      $s15 = "\\woy]Ytt^WzTUPm{~6[?o!]" fullword ascii
      $s16 = "\\ytQGBrgs" fullword ascii
      $s17 = "saYIhbsFxidQGBrgsSuaMHhbsFxidQi6" fullword ascii
      $s18 = "tFVRaA4" fullword ascii
      $s19 = "\\eeQGBrgsb" fullword ascii
      $s20 = "\\`gKtfQoeQWa~hbsv" fullword ascii
   condition:
      uint16(0) == 0x484d and filesize < 1000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

