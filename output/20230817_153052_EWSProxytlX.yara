/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-17
   Identifier: MP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule EwsProxy {
   meta:
      description = "MP - file EwsProxy.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "5cfe722df5e35984850be9d32a3a35a3e0c09c8ba1738ed97d39dd489c863b63"
   strings:
      $x1 = "CEWSProxyProcess::Close - CloseHandle(m_hMutex) failed." fullword wide
      $s2 = "NGEWSProxy::CInitializeServerCommand::Execute" fullword wide
      $s3 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publ" ascii
      $s4 = "CEWSProxyProcess::Close - CloseHandle(m_hMapFile) failed." fullword wide
      $s5 = "DiscoveryLibProxyCom - SearchByAddress failed to get the discovery interface, HR = 0x%08X" fullword wide
      $s6 = "NGBusinessLogic::CThreadedCommandReceiver::TargetReceiverThreadStub" fullword wide
      $s7 = "NGBusinessLogic::CThreadedCommandReceiver::TargetReceiverThread" fullword wide
      $s8 = "EWSProxy.Exe" fullword wide
      $s9 = "AEWSProxyProcess.cpp" fullword wide
      $s10 = "ShellExec.cpp" fullword wide
      $s11 = "DiscoveryLibProxyCom - SearchByAddress - No Address was passed in. Aborting search." fullword wide
      $s12 = "NGEWSProxy::CClientRequest::DoPostProcessing" fullword wide
      $s13 = "InstanceFinderDlgUI.dll" fullword wide
      $s14 = "NGBusinessLogic::CCommandReceiver::WaitAndProcess" fullword wide
      $s15 = "FD - pPropertyStore->GetValue(PKEY_PNPX_FriendlyName, &propVar); failed for i =%d" fullword wide
      $s16 = "GetPrinterDataValue - OpenPrinter(%s) failed" fullword wide
      $s17 = "DiscoveryLibProxyCom - SearchById failed to get the discovery interface, HR = 0x%08X" fullword wide
      $s18 = "DiscoveryLibProxyCom - SearchByType failed to get the discovery interface, HR = 0x%08X" fullword wide
      $s19 = "CPrintUtils::GetMonitorNameFromPortName - g_pSpoolerApi->EnumPorts did not return ERROR_INSUFFICIENT_BUFFER" fullword wide
      $s20 = "CPrintUtils::GetMonitorNameFromPortName - g_pSpoolerApi->EnumPorts failed" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule EwsProxyUI {
   meta:
      description = "MP - file EwsProxyUI.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "1b552e25d97d09fb1fa0e74bef194454f6c3b5c1840a20fc7a46c79096d165cc"
   strings:
      $x1 = ".lib section in a.out corruptedCentral Brazilian Standard TimeMountain Standard Time (Mexico)W. Central Africa Standard Timebad " ascii
      $x2 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii
      $x3 = "mismatched count during itab table copymspan.sweep: bad span state after sweepout of memory allocating heap arena mapruntime: bl" ascii
      $x4 = " to unallocated spanArabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreateProcessAsUserWCryptAcquireContextWEgyptian" ascii
      $x5 = "unixpacketunknown pcws2_32.dll  of size   (targetpc= KiB work,  gcwaiting= heap_live= idleprocs= in status  m->mcache= mallocing" ascii
      $x6 = "Bidi_ControlFindNextFileGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempPathWJoin_ControlKernel32.dllLoadLibr" ascii
      $x7 = "workbuf is empty initialHeapLive= spinningthreads=, s.searchAddr = : missing method DnsRecordListFreeFLE Standard TimeGC assist " ascii
      $x8 = "Nyiakeng_Puachue_HmongPakistan Standard TimeParaguay Standard TimeSakhalin Standard TimeSao Tome Standard TimeTasmania Standard " ascii
      $x9 = "file descriptor in bad statefindrunnable: netpoll with pgcstopm: negative nmspinninginvalid runtime symbol tablemheap.freeSpanLo" ascii
      $x10 = "Variation_Selectorbad manualFreeListconnection refusedfile name too longforEachP: not donegarbage collectionidentifier removedin" ascii
      $x11 = "structure needs cleaning bytes failed with errno= to unused region of span with too many arguments AUS Central Standard TimeAUS " ascii
      $x12 = "bad flushGen bad map statedalTLDpSugct?exchange fullfatal error: gethostbynamegetservbynamekernel32.dll" fullword ascii
      $x13 = "pi32.dllbad flushGenbad g statusbad g0 stackbad recoverycan't happencas64 failedchan receivedumping heapend tracegc" fullword ascii
      $x14 = "entersyscallgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dllmadvdontneednetapi32.dllnot pollablereleasep" ascii
      $x15 = "bytes.Buffer: reader returned negative count from ReadgcControllerState.findRunnable: blackening not enabledinternal error: poll" ascii
      $s16 = " VirtualQuery failed; errno=runtime: bad notifyList size - sync=runtime: invalid pc-encoded table f=runtime: invalid typeBitsBul" ascii
      $s17 = "swsock.dllruntime: P runtime: p scheddetailsecur32.dllshell32.dllshort writetracealloc(unreachableuserenv.dll KiB total,  [recov" ascii
      $s18 = "Bidi_ControlFindNextFileGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempPathWJoin_ControlKernel32.dllLoadLibr" ascii
      $s19 = "kakuiOld_HungarianRegDeleteKeyWRegEnumKeyExWRegEnumValueWRegOpenKeyExWVirtualUnlockWriteConsoleWadvapi32.dll" fullword ascii
      $s20 = "= flushGen  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= sweepgen  sweepgen= targetpc= throwing= until " ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule ProxyLog {
   meta:
      description = "MP - file ProxyLog.dat"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-17"
      hash1 = "482e467680750003c2d5d4819ba7f8dd65e2fbfcf72023f1034255294c879368"
   strings:
      $s1 = "726lJCvpfaAHmQMKokllJCvpfaAHmQMKokllJCvpfaAHmQMKokllJCvpfaAHmQMKokllJCvpfaAHmQMKokllJCvpfaAHmQMKokllJCvpfaAHmQMKokllJCvpfaAHmQMK" ascii
      $s2 = "Aem6M.okl" fullword ascii
      $s3 = "Aem3M.okl" fullword ascii
      $s4 = "Aem5M.okl" fullword ascii
      $s5 = "Aem4M.okl" fullword ascii
      $s6 = "DEmAMK2" fullword ascii
      $s7 = "AftraA0" fullword ascii
      $s8 = "cQVmQM7" fullword ascii
      $s9 = "fAfpfaAHmQMKokllJCv4" fullword ascii
      $s10 = "bALzQMKokllJCvpfaAHmQMKokllJCvpfaAHmQM3" fullword ascii
      $s11 = "`F`A -" fullword ascii
      $s12 = "BXlQMK6032" fullword ascii
      $s13 = "EmQMK6427" fullword ascii
      $s14 = "AfHfaA0" fullword ascii
      $s15 = "AfTbaA0" fullword ascii
      $s16 = "cQfmQM3" fullword ascii
      $s17 = "]SMKokll" fullword ascii
      $s18 = "faAEmQM" fullword ascii
      $s19 = "}Ioko!" fullword ascii
      $s20 = "A-m5MFoallJCv\"fWAxm`M}oflfJnvPf" fullword ascii
   condition:
      uint16(0) == 0x6f4b and filesize < 600KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

