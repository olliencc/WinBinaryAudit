
/*
Released as open source by NCC Group Plc - http://www.nccgroup.com/
 
Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

http://www.github.com/olliencc/WinBinaryAudit/
 
Released under AGPL see LICENSE for more information
*/

using System;
using System.Collections.Generic;
using System.Text;
using System.Drawing;


namespace WinBinAuditv1
{
    public class SecurityInfo
    {
        public string FileName;
        public bool IsPE;
        public bool IsKernel;
        public bool Success;
        public string Type;
        public string Is32or64bit;
        public List<String> CompilerVer;
        public string LinkerVer;
        public string Platform;
        public bool NoSEH;
        public bool SafeSEH;
        public bool DEP;
        public bool ASLR;
        public bool GS1;
        public bool DLLPlanting;
        public string DLLPlantReason;
        public int GS1Which;
        public int GS2;
        public string UACUIAccess;
        public string UACIntegrityLvl;
        public bool HeapSetInformation;
        public bool LoadLibrary;
        public bool SetDEPPolicy;
        public bool EncodePointer;
        public bool VirtualAlloc;
        public bool ProcessHeapExec;
        public bool InsecureSection;
        public bool ForceInt;
        public bool DotNet;
        public string DotNetVer;
        public bool DotNetFullyManaged;
        public bool DotNetStrongName;
        public bool DotNetAllowPartialTrustCallers;
        public bool DotNetSkipValidation;
        public int MSSDLCBannedCount;
        public string MSSDLCBannedList;
        public string Error;
        public string Manifest;
        public string[] Imports;
        public string MD5;
        public string SHA1;
        public string SHA2;
        public string Vendor;
        public string SigName;
        public string SigAlgo;
        public string SigIssuer;
        public Icon BinIcon;
        public long FileSize;
        public bool AppContainer;
        public bool MS12001;
        public int MS12001Sz;
        public uint MS12001SzTwo;
        public uint CodeSz;
        public bool isDLL;
        public string[] DelayImports;
        public bool bDelayLoaded;
        public string Version;
        public bool HighEntropy;
        public bool CFG;

        public SecurityInfo()
        {
            this.FileName = null;
            this.IsPE = false;
            this.IsKernel = false; 
            this.Success = false;
            this.Type = null;
            this.Is32or64bit = null;
            this.CompilerVer = null;
            this.LinkerVer = null;
            this.Platform = null;
            this.NoSEH = false;
            this.SafeSEH = false;
            this.DEP = false;
            this.ASLR = false;
            this.GS1 = false;
            this.GS1Which = 0;
            this.GS2 = 0;
            this.UACUIAccess = null;
            this.UACIntegrityLvl = null;
            this.HeapSetInformation = false;
            this.SetDEPPolicy = false;
            this.VirtualAlloc = false;
            this.EncodePointer = false;
            this.ProcessHeapExec = false;
            this.InsecureSection = false;
            this.ForceInt = false;
            this.DotNet = false;
            this.DotNetVer = null;
            this.DotNetFullyManaged = false;
            this.DotNetStrongName = false;
            this.DotNetAllowPartialTrustCallers = false;
            this.DotNetSkipValidation = false;
            this.MSSDLCBannedCount = 0;
            this.MSSDLCBannedList = null;
            this.Error = null;
            this.Manifest = null;
            this.Imports = null;
            this.MD5 = null;
            this.SHA1 = null;
            this.SHA2 = null;
            this.Vendor = null;
            this.SigName = null;
            this.SigAlgo = null;
            this.SigIssuer = null;
            this.LoadLibrary = false;
            this.DLLPlanting = false;
            this.DLLPlantReason = null;
            this.FileSize = 0;
            this.AppContainer = false;
            this.MS12001 = false;
            this.MS12001Sz = 0;
            this.MS12001SzTwo = 0;
            this.CodeSz = 0;
            this.isDLL = false;
            this.DelayImports = null;
            this.bDelayLoaded = false;
            this.Version = null;
            this.HighEntropy = false;
            this.CFG = false;
        }
    }
}
