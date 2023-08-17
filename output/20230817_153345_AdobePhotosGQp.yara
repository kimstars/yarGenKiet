/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule AdobePhotosGQp_AdobeDB {
   meta:
      description = "MP - file AdobeDB.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "98f139983882e443116863f795c1df50dae5ceb971075914dfee264dc1502a09"
   strings:
      $s1 = "b2n.RGR=R4jbAnrRbRJ" fullword ascii
      $s2 = "R:R4jXAAr}b%J%G" fullword ascii
      $s3 = "uRGjBAn.RbRQboZop|CdS" fullword ascii
      $s4 = "flriLtB.pLBd" fullword ascii
      $s5 = "MBrjbA>)Ur.JRG" fullword ascii
      $s6 = "rRbRJ]X.bAa" fullword ascii
      $s7 = "bdn.RbRoR&j" fullword ascii
      $s8 = "JGjbInrRBRJR8jbA" fullword ascii
      $s9 = "npR`RHREj`AlrPbPJPGhbCnpR`RHREj`AlrPbPJPGzbQnbRrRjRGjbAnrRbRJRGjbAnrRbRJRGjbAnrRbRJRGjbAnrRbRJRGjbAnrRbRJRGjbAnrRbRJRGjbAnrRbRJR" ascii
      $s10 = "JRG.bAn" fullword ascii
      $s11 = "UbB.UGH" fullword ascii
      $s12 = "bdn.RbRGRMjbA" fullword ascii
      $s13 = "b2n.RbRoR0j" fullword ascii
      $s14 = "F:\"ZEjb+n" fullword ascii
      $s15 = "bRJRGjbAnrRbRJRGjbAnrRbRJRGjbAnrRbRJRGjbAnrRbRJRGjbAnRRBRjRgjBANrrbrJrGBbinZRJRbRgjBANrrbrJrGJbanRRBRjRgjBANrrbrJrGJb" fullword ascii
      $s16 = "eBARGj2" fullword ascii
      $s17 = "eQacVF4" fullword ascii
      $s18 = "vNSGjWm7" fullword ascii
      $s19 = "eBeRGj2" fullword ascii
      $s20 = "ZbRgwk7" fullword ascii
   condition:
      uint16(0) == 0x5272 and filesize < 1000KB and
      8 of them
}

rule AdobeHelp {
   meta:
      description = "MP - file AdobeHelp.cpl"
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
      hash1 = "39f9157e24fa47c400d4047c1f6d9b4dbfd067288cfe5f5c0cc2e8449548a6e8"
   strings:
      $s1 = "igViHkionwr.dll" fullword ascii
      $s2 = " Type Descriptor'" fullword ascii
      $s3 = "qfpxwihovvl" fullword ascii
      $s4 = "wnjaxpcojfyphlwuuucmp" fullword ascii
      $s5 = "droesvqnevvucgxqejojaprkavnefh" fullword ascii
      $s6 = "nghrwitwrpbufgfregfcneuueelsaexbdcrrgsomsale" fullword ascii
      $s7 = "lxqdshilptdiospmjy" fullword ascii
      $s8 = "pusaxcvnocxdkpkixjixjywpbcwqfjtxstqmtpp" fullword ascii
      $s9 = "ocvnrcbjnpftbylnrqwkhunupotdulau" fullword ascii
      $s10 = "pcdOpenSession" fullword ascii
      $s11 = " Class Hierarchy Descriptor'" fullword ascii
      $s12 = " Base Class Descriptor at (" fullword ascii
      $s13 = " Complete Object Locator'" fullword ascii
      $s14 = "61787<7@7D7H7L7P7T7" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "5 5$5(5Q5w5" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "8!999C9_9f9l9z9" fullword ascii /* Goodware String - occured 1 times */
      $s17 = " delete[]" fullword ascii
      $s18 = ">J>P>V>\\>b>h>o>v>}>" fullword ascii /* Goodware String - occured 2 times */
      $s19 = " delete" fullword ascii
      $s20 = "C0I0U0" fullword ascii /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
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

/* Super Rules ------------------------------------------------------------- */

