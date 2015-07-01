/*
Released as open source by NCC Group Plc - http://www.nccgroup.com/
 
Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

http://www.github.com/olliencc/WinBinaryAudit/
 
Released under AGPL see LICENSE for more information
*/


using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ManagedMD;
using WinBinAuditv1;
using WinBinAuditv1PE;

namespace WinBinAudit
{
    public class v5
    {

        public PEFile OpenPE;
        public WinBinAuditv1.SecurityInfo SecInfo;
        private PEProp OpenPEBI;

        /// <summary>
        /// Constructor
        /// </summary>
        public v5()
        {


        }

        /// <summary>
        /// Processes a file results are in the SecInfo object of file
        /// </summary>
        /// <param name="strFile">Full path to file to analyze</param>
        public void ProcessFile(string strFile)
        {

            SecInfo = new WinBinAuditv1.SecurityInfo();

            try
            {
                this.OpenPE = new PEFile(strFile);
                this.OpenPEBI = new PEProp(strFile);
                WinBinAuditv1PEChecks PEChecks = new WinBinAuditv1PEChecks();

                SecInfo.MD5 = this.OpenPEBI.MD5Hash.ToString();
                SecInfo.SHA1 = this.OpenPEBI.SHA1Hash.ToString();


                // 
                if (OpenPEBI.PE.IsPEFile == true)
                {
                    SecInfo.Type = "PE";
                    SecInfo.IsPE = true;
                    SecInfo.Platform = OpenPEBI.Machine.ToString();
                    if (SecInfo.Platform.Contains("UNKNOWN") == true) return;
                    try
                    {
                        SecInfo.LinkerVer = OpenPEBI.LinkerVersion.ToString();
                    }
                    catch (Exception)
                    {
                        SecInfo.LinkerVer = "UNKNOWN";
                    }
                }
                else
                {
                    SecInfo.IsPE = false;
                    return;
                }

                if (OpenPEBI.PE.Is64Bit == true)
                {
                    SecInfo.Is32or64bit = "64";
                    StringBuilder sbType = new StringBuilder();
                    sbType.Append("PE+");
                    SecInfo.Type = sbType.ToString();
                }
                else
                {
                    SecInfo.Is32or64bit = "32";
                    StringBuilder sbType = new StringBuilder();
                    sbType.Append("PE");
                    SecInfo.Type = sbType.ToString();
                }

                if (OpenPEBI.Kernel == true)
                {
                    SecInfo.IsKernel = true;
                }
                else
                {
                    SecInfo.IsKernel = false;

                    if (PEChecks.IsDLL(this.OpenPEBI))
                    {
                        SecInfo.isDLL = true;
                    }
                    else
                    {
                        SecInfo.isDLL = false;
                    }

                    if (PEChecks.GetManifest(this.OpenPEBI, SecInfo))
                    {
                        string UACLvl = PEChecks.UACIntLevel(this.OpenPEBI);
                        SecInfo.UACIntegrityLvl = UACLvl;
                        string UACUI = PEChecks.UACUIAccess(this.OpenPEBI);
                        SecInfo.UACUIAccess = UACUI;
                    }
   
                    if (OpenPEBI.Managed == true)
                    {
                        SecInfo.DotNet = true;
                        if (OpenPEBI.ManagedP)
                        {
                            SecInfo.DotNetFullyManaged = true;
                        }
                        else
                        {
                            SecInfo.DotNetFullyManaged = false;
                        }

                        try
                        {
                            if (OpenPEBI.SkipValidation)
                            {
                                SecInfo.DotNetSkipValidation = true;
                            }
                            else
                            {
                                SecInfo.DotNetSkipValidation = false;
                            }
                        }
                        catch (Exception)
                        {
                            SecInfo.DotNetSkipValidation = false;
                        }

                        if (PEChecks.DotNetStrongName(this.OpenPEBI) == true)
                        {
                            SecInfo.DotNetStrongName = true;
                        }

                        if (PEChecks.DotNetAllowPartialTrustCallers(this.OpenPEBI) == true)
                        {
                            SecInfo.DotNetAllowPartialTrustCallers = true;
                        }

                        SecInfo.DotNetVer = PEChecks.DotNetVer(this.OpenPEBI).ToString();
                        if (SecInfo.DotNetVer.ToString() == "")
                        {
                            SecInfo.DotNetVer = new StringBuilder("Unknown").ToString();
                        }
     
                        if (PEChecks.NoSEH(this.OpenPEBI) == true)
                        {
                            SecInfo.NoSEH = true;
                        }
                        else if (PEChecks.SafeSEH(this.OpenPEBI) == true)
                        {
                            SecInfo.SafeSEH = true;
                        }


                    }
                    else
                    {
                        SecInfo.Imports = OpenPEBI.ImportFunctionsGet(OpenPE);
                        SecInfo.bDelayLoaded = OpenPEBI.DelayLoadImports(OpenPE);
                        if (SecInfo.bDelayLoaded)
                        {
                            SecInfo.DelayImports = OpenPEBI.DelayLoadImportFunctionsGet(OpenPE, strFile);
                        }

                        if (SecInfo.Imports != null)
                        {
                            // FIX
                            SecInfo.MSSDLCBannedCount = PEChecks.MSBannedAPIs(SecInfo, SecInfo.Imports);
                        }
                     

                        if (PEChecks.NX(this.OpenPEBI) == true)
                        {
                            SecInfo.DEP = true;
                        }


                        if (PEChecks.NoSEH(this.OpenPEBI) == true)
                        {

                            SecInfo.NoSEH = true;
                        }
                        else if (PEChecks.SafeSEH(this.OpenPEBI) == true)
                        {
                            SecInfo.SafeSEH = true;
                        }


                        if (PEChecks.AppContainer(this.OpenPEBI) == true)
                        {
                            SecInfo.AppContainer = true;
                        }

                        if(PEChecks.ControlFlowGuard(this.OpenPEBI) == true)
                        {
                            SecInfo.CFG = true;
                        }
   
                        if (PEChecks.MS12001(this.OpenPEBI) == true)
                        {
                            SecInfo.MS12001 = true;
                        }


                        SecInfo.MS12001Sz = PEChecks.MS12001Sz(this.OpenPEBI);
                        SecInfo.MS12001SzTwo = PEChecks.MS12001SzTwo(this.OpenPEBI);

                        SecInfo.CodeSz = PEChecks.CodeSize(this.OpenPEBI);

                        if (PEChecks.ASLR(this.OpenPEBI) == true)
                        {
                            SecInfo.ASLR = true;
                        }


                        if (PEChecks.InsecureSection(this.OpenPEBI) == true)
                        {
                            SecInfo.InsecureSection = true;
                        }


                        if (PEChecks.HeapSetInfo(this.OpenPEBI, SecInfo) == true)
                        {
                            SecInfo.HeapSetInformation = true;
                        }


                        if (PEChecks.LoadLibrary(this.OpenPEBI, SecInfo) == true)
                        {
                            SecInfo.LoadLibrary = true;
                        }


                        if (PEChecks.DLLPlanting(this.OpenPEBI, SecInfo) == true)
                        {
                                SecInfo.DLLPlanting = true;
                                SecInfo.DLLPlantReason = PEChecks.DLLPlantingReason(this.OpenPEBI, this.SecInfo);
                        }


                        if (PEChecks.VirtualAlloc(this.OpenPEBI, SecInfo) == true)
                        {
                            SecInfo.VirtualAlloc = true;
                        }



                        if (PEChecks.EncodePointer(this.OpenPEBI, SecInfo) == true)
                        {
                            SecInfo.EncodePointer = true;
                        }


                        if (PEChecks.SetDEPPolicy(this.OpenPEBI, SecInfo) == true)
                        {
                            SecInfo.SetDEPPolicy = true;
                        }


                        if (PEChecks.ForceInt(this.OpenPEBI) == true)
                        {
                            SecInfo.ForceInt = true;
                        }


                        if (PEChecks.ProcessHeapExec(this.OpenPEBI) == true)
                        {
                            SecInfo.ProcessHeapExec = true;
                        }
       

                        if (this.OpenPE.Is64Bit == false)
                        {
                            if (PEChecks.GS1Check(this.OpenPEBI) == true)
                            {
                                SecInfo.GS1 = true;
                                SecInfo.GS1Which = 1;
                            }
                            else
                            {
                            }

                            if (PEChecks.GS3Check(this.OpenPEBI, SecInfo) == true)
                            {
                                SecInfo.GS1 = true;
                                if (SecInfo.GS1Which == 1)
                                {
                                    SecInfo.GS1Which = 3;
                                }
                                else
                                {
                                    SecInfo.GS1Which = 2;
                                }
                            }
          
                        }

                        if (this.OpenPE.Is64Bit == false)
                        {
                            int intGS2 = PEChecks.GS2Check32(this.OpenPEBI);
                            if (intGS2 > 0)
                            {
                                SecInfo.GS2 = intGS2;
                            }

                        }
                        else
                        {
                            bool bGS = PEChecks.GSCheck64(this.OpenPEBI);
                            SecInfo.GS1 = bGS;
                        }

                        SecInfo.CompilerVer = PEChecks.MSCompilerVers(this.OpenPEBI);

                    }

                    // From file properties
                    try
                    {
                        SecInfo.Vendor = OpenPEBI.Vendor.ToString();
                    }
                    catch (Exception)
                    {
                        SecInfo.Vendor = "N/A";

                    }


                    // From file properties
                    try
                    {
                        SecInfo.Version = OpenPEBI.Version.ToString();
                    }
                    catch (Exception)
                    {
                        SecInfo.Version = "N/A";

                    }

                    // Digital Signature
                    PEChecks.SigDetails(SecInfo, this.OpenPEBI);

                    // File size
                    PEChecks.GetFileSize(SecInfo, this.OpenPEBI);


                    if (this.OpenPE.Is64Bit == true)
                    {
                        SecInfo.HighEntropy = PEChecks.HighEntropy(SecInfo,this.OpenPEBI);
                    }
                    SecInfo.Success = true;

                }
            }
            catch (System.Threading.ThreadAbortException)
            {

            }
            catch (Exception exception)
            {

                SecInfo.Success = false;
                StringBuilder strErrorLocal = new StringBuilder();
                DateTime current = DateTime.Now;
                strErrorLocal.Append("Couldn't process " + strFile + " - " + exception.ToString());
                SecInfo.Error = strErrorLocal.ToString();

                try
                {
                    SecInfo.Vendor = OpenPEBI.Vendor.ToString();
                }
                catch (Exception)
                {
                    SecInfo.Vendor = "N/A";

                }

            }
        }
    }
}
