/*
Released as open source by NCC Group Plc - http://www.nccgroup.com/
 
Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

http://www.github.com/olliencc/WinBinaryAudit/
 
Released under AGPL see LICENSE for more information
*/

using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Windows.Forms;
using ManagedMD;
using ManagedMD.Utils;
using WinBinAuditv1PE;
using System.Runtime.InteropServices;         
using System.Security.Cryptography.X509Certificates;

namespace WinBinAuditv1
{
    class WinBinAuditv1PEChecks
    {

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);
        [DllImport("kernel32.dll")]
        static extern IntPtr FindResource(IntPtr hModule, int lpID, int lpType);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint SizeofResource(IntPtr hModule, IntPtr hResInfo);
        [DllImport("User32.dll")]
        static extern int LoadString(IntPtr hInstance, int uID, StringBuilder lpBuffer, int nBufferMax);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr LockResource(IntPtr hResData);

        /// <summary>
        /// Check for DEP Support
        /// </summary>
        /// <param name="binInfo"></param>
        /// <returns></returns>
        public bool NX(PEProp binInfo)
        {
            try
            {
                ImageOptionalHeader optionalHeader = binInfo.PE.OptionalHeader;
                if (optionalHeader != null)
                {
                    ushort field = (ushort)optionalHeader.GetField(ImageOptionalHeader.Fields.DllCharacteristics);
                    if ((field & 0x100) != 0)
                    {
                        return true;
                    }
                }
                else
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
            return false;
        }

        /// <summary>
        /// SafeSEH Check
        /// </summary>
        /// <param name="binInfo"></param>
        /// <returns></returns>
        public bool SafeSEH(PEProp binInfo)
        {
            try
            {
                ImageOptionalHeader optionalHeader = binInfo.PE.OptionalHeader;
                if (optionalHeader != null)
                {
                    ushort field = (ushort)binInfo.PE.OptionalHeader.GetField(ImageOptionalHeader.Fields.DllCharacteristics);
                    if ((field & 0x400) != 0)
                    {
                        return false;
                    }
                    SafePointer rva = (SafePointer)binInfo.PE.OptionalHeader.DirectoryEntries[10].GetField(ImageDataDirectory.Fields.VirtualAddress);
                    if (rva.Address == 0)
                    {
                        return false;
                    }
                    uint DirSize = (uint)binInfo.PE.OptionalHeader.DirectoryEntries[10].GetField(ImageDataDirectory.Fields.Size);
                    ImageLoadConfigDirectory32 directory = new ImageLoadConfigDirectory32(binInfo.PE.RVA2VA(rva));
                    int FieldSize = (int)directory.GetField(ImageLoadConfigDirectory32.Fields.Size);
                    if (FieldSize < 0x48)
                    {
                        return false;
                    }
                    uint SEHTable = (uint)directory.GetField(ImageLoadConfigDirectory32.Fields.SEHandlerTable);
                    uint SEHTableCount = (uint)directory.GetField(ImageLoadConfigDirectory32.Fields.SEHandlerCount);
                    if ((SEHTable != 0) && (SEHTableCount != 0))
                    {
                        return true;
                    }
                    if (SEHTable == 0)
                    {
                        return false;
                    }
                    if (SEHTableCount == 0)
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
            return false;
        }

        /// <summary>
        /// Check for No SEH
        /// </summary>
        /// <param name="binInfo"></param>
        /// <returns></returns>
        public bool NoSEH(PEProp binInfo)
        {
            try
            {
                ImageOptionalHeader optionalHeader = binInfo.PE.OptionalHeader;
                if (optionalHeader != null)
                {
                    ushort field = (ushort)binInfo.PE.OptionalHeader.GetField(ImageOptionalHeader.Fields.DllCharacteristics);
                    if ((field & 0x400) != 0)
                    {
                        return true;
                    }
                }
            }
            catch (Exception)
            {
                return false;
            }
            return false;
        }

        /// <summary>
        /// Is the file a DLL
        /// </summary>
        /// <param name="binInfo"></param>
        /// <returns></returns>
        public bool IsDLL(PEProp binInfo)
        {
            // IMAGE_FILE_DLL

            try
            {
                ushort field = (ushort)binInfo.PE.FileHeader.GetField(ImageFileHeader.Fields.Characteristics);
                if (( field & 0x2000) != 0)
                {
                    return true;
                }
            } 
            catch (Exception)
            {
                return false;
            }
            return false;
        }

        /// <summary>
        /// MS12-001 Vulnerability Check
        /// 
        /// </summary>
        /// <param name="binInfo"></param>
        /// <returns></returns>
        public bool MS12001(PEProp binInfo){
            try
            {
                ImageOptionalHeader optionalHeader = binInfo.PE.OptionalHeader;
                if (optionalHeader != null)
                {
                    SafePointer rva = (SafePointer)binInfo.PE.OptionalHeader.DirectoryEntries[10].GetField(ImageDataDirectory.Fields.VirtualAddress);
                    if (rva.Address == 0)
                    {
                        return false;
                    }
                    uint DirSize = (uint)binInfo.PE.OptionalHeader.DirectoryEntries[10].GetField(ImageDataDirectory.Fields.Size);

                    // This used to be != 64
                    // http://blogs.technet.com/b/srd/archive/2012/01/10/more-information-on-the-impact-of-ms12-001.aspx
                    if (DirSize == 0x48)
                    {
                        return true;
                    }

                    /*
                    ImageLoadConfigDirectory32 directory = new ImageLoadConfigDirectory32(binInfo.PE.RVA2VA(rva));
                    int FieldSize = (int)directory.GetField(ImageLoadConfigDirectory32.Fields.Size);
                    if (FieldSize != 64)
                    {
                        return true;
                    }
                     */
                }
                else
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
            return false;
        }

        /// <summary>
        /// Size extraction related to MS12-001 size check
        /// </summary>
        /// <param name="binInfo"></param>
        /// <returns></returns>
        public int MS12001Sz(PEProp binInfo){
            try
            {
                ImageOptionalHeader optionalHeader = binInfo.PE.OptionalHeader;
                if (optionalHeader != null)
                {
                    SafePointer rva = (SafePointer)binInfo.PE.OptionalHeader.DirectoryEntries[10].GetField(ImageDataDirectory.Fields.VirtualAddress);
                    if (rva.Address == 0)
                    {
                        return 0;
                    }
                    uint DirSize = (uint)binInfo.PE.OptionalHeader.DirectoryEntries[10].GetField(ImageDataDirectory.Fields.Size);
                    
                    ImageLoadConfigDirectory32 directory = new ImageLoadConfigDirectory32(binInfo.PE.RVA2VA(rva));
                    int FieldSize = (int)directory.GetField(ImageLoadConfigDirectory32.Fields.Size);
                    return FieldSize;
                }
                else
                {
                    return 0;
                }
            }
            catch (Exception)
            {
                return 0;
            }
            //return 0;
        }

        /// <summary>
        /// Second size extraction for MS12-001 test
        /// </summary>
        /// <param name="binInfo"></param>
        /// <returns></returns>
        public uint MS12001SzTwo(PEProp binInfo)
        {
            try
            {
                ImageOptionalHeader optionalHeader = binInfo.PE.OptionalHeader;
                if (optionalHeader != null)
                {
                    SafePointer rva = (SafePointer)binInfo.PE.OptionalHeader.DirectoryEntries[10].GetField(ImageDataDirectory.Fields.VirtualAddress);
                    if (rva.Address == 0)
                    {
                        return 0;
                    }

                    uint DirSize = (uint)binInfo.PE.OptionalHeader.DirectoryEntries[10].GetField(ImageDataDirectory.Fields.Size);

                    return DirSize;
                }
                else
                {
                    return 0;
                }
            }
            catch (Exception)
            {
                return 0;
            }
            //return 0;
        }
        

        /// <summary>
        /// Is this an AppContainer binary
        /// </summary>
        /// <param name="binInfo"></param>
        /// <returns></returns>
        public bool AppContainer(PEProp binInfo)
        {
            try
            {
                ImageOptionalHeader optionalHeader = binInfo.PE.OptionalHeader;
                if (optionalHeader != null)
                {
                    ushort Field = (ushort)optionalHeader.GetField(ImageOptionalHeader.Fields.DllCharacteristics);
                    if ((Field & 0x1000) != 0)
                    {
                        return true;
                    }

                }
                else
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }

            return false;

        }

        /// <summary>
        /// Is this an AppContainer binary
        /// </summary>
        /// <param name="binInfo"></param>
        /// <returns></returns>
        public bool ControlFlowGuard(PEProp binInfo)
        {
            try
            {
                ImageOptionalHeader optionalHeader = binInfo.PE.OptionalHeader;
                if (optionalHeader != null)
                {
                    ushort Field = (ushort)optionalHeader.GetField(ImageOptionalHeader.Fields.DllCharacteristics);
                    if ((Field & 0x4000) != 0)
                    {
                        return true;
                    }

                }
                else
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }

            return false;

        }

        /// <summary>
        /// Does it support ASLR
        /// </summary>
        /// <param name="binInfo"></param>
        /// <returns></returns>
        public bool ASLR(PEProp binInfo)
        {
            
            try
            {
                ImageOptionalHeader optionalHeader = binInfo.PE.OptionalHeader;
                if (optionalHeader != null)
                {
                    ushort field = (ushort) optionalHeader.GetField(ImageOptionalHeader.Fields.DllCharacteristics);
                    if ((field & 0x40) != 0)
                    {
                        return true;
                    }
                }
                else
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
            
            return false;
        }

        
        /// <summary>
        /// Is there a shared and writeable section
        /// </summary>
        /// <param name="binInfo"></param>
        /// <returns></returns>
        public bool InsecureSection(PEProp binInfo)
        {
            bool bFailed = false;

            try
            {
                ImageSectionHeader[] sectionHeaders = binInfo.PE.SectionHeaders;
                if (sectionHeaders != null)
                {
                    foreach (ImageSectionHeader header in sectionHeaders)
                    {
                        uint field = (uint)header.GetField(ImageSectionHeader.Fields.Characteristics);
                        if ((field & 0x90000000) == 0x90000000)
                        {
                            bFailed = true;
                        }
                    }

                    if (bFailed == true)
                    {
                        return true;
                    }

                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
            return true;

        }

        // .NET Strong Name
        public bool DotNetStrongName(PEProp binInfo)
        {
            try
            {
                Assembly assembly = new Assembly(binInfo.Path);
                byte[] publicKey = assembly.PublicKey;
                if ((publicKey != null) && (publicKey.Length > 0))
                {
                    return true;
                }
            }
            catch (Exception)
            {
                return false;
            }
   
            return false;
        }

        // .NET Allow Partially Trusted Callers
        public bool DotNetAllowPartialTrustCallers(PEProp binInfo)
        {
            try
            {
                Assembly assembly = new Assembly(binInfo.Path);
                CustomAttribute[] customAttributes = assembly.CustomAttributes;
                if (customAttributes == null)
                {
                    return false;
                }
                foreach (CustomAttribute attribute in customAttributes)
                {
                    if (attribute.TypeCtor.Type.Name == "AllowPartiallyTrustedCallersAttribute")
                    {
                        return true;
                    }
                }
            }
            catch (Exception)
            {
                return false;
            }

            return false;
        }

        public string DotNetVer(PEProp binInfo)
        {
            bool bMaj = false;
            bool bMin = false;
            string strMaj = null;
            string strMin = null ;

            COMPEFile comPE = new COMPEFile(binInfo.PE);
            ImageCor20Header cor20Hdr = comPE.Cor20Header;
            Header.FieldInfo fieldInfo = new Header.FieldInfo();
            object fieldValue = new object();

            for(int intCount = 0;intCount < cor20Hdr.NumberOfFields; intCount++){
                fieldInfo = cor20Hdr.GetFieldInfo(intCount);
                if (fieldInfo.Name.ToString() == "MajorRuntimeVersion")
                {
                    bMaj = true;
                    fieldValue  = cor20Hdr.GetField(intCount);

                    strMaj = fieldValue.ToString();
                } else if (fieldInfo.Name.ToString() == "MinorRuntimeVersion"){
                    bMin = true;
                    fieldValue  = cor20Hdr.GetField(intCount);

                    strMin = fieldValue.ToString();
                }
            }

            StringBuilder strFinal = new System.Text.StringBuilder();

            if (bMaj == true && bMin == true)
            {
                strFinal.Append(strMaj.ToString());
                strFinal.Append(".");
                strFinal.Append(strMin.ToString());
            }
            else
            {
                strFinal.Append("Error");
            }

            return strFinal.ToString();
        }

        public bool VirtualAlloc(PEProp binInfo, SecurityInfo SecInfo)
        {

            foreach (string strImport in SecInfo.Imports)
            {

                if (strImport.ToString() == "VirtualAlloc") return true;
            }

            return false;
        }

        public uint CodeSize(PEProp binInfo){
            uint szSize = 0;

            ImageSectionHeader[] sectionHeaders = binInfo.PE.SectionHeaders;
            if (sectionHeaders != null)
            {
                foreach (ImageSectionHeader header in sectionHeaders)
                {
                    uint field = (uint)header.GetField(ImageSectionHeader.Fields.Characteristics);
                    if ((field & 0x20000000) != 0)
                    {
                        szSize += (uint)header.GetField(ImageSectionHeader.Fields.SizeOfRawData);
                    }
                }

            }

            return szSize;
        }

        /// <summary>
        /// SetDllDirectory, SetDefaultDllDirectories, AddDllDirectory
        /// </summary>
        /// <param name="binInfo"></param>
        /// <param name="secInfo"></param>
        /// <returns></returns>
        public bool DLLPlanting(PEProp binInfo, SecurityInfo SecInfo)
        {

            if (DoesImport(binInfo, "SetDLLDirectory", false, SecInfo) || DoesImport(binInfo, "SetDefaultDllDirectories", false, SecInfo) || DoesImport(binInfo, "AddDllDirectory", false, SecInfo))
            {
                if (DoesImport(binInfo, "SetDLLDirectory", false, SecInfo)){
                    SecInfo.DLLPlantReason = SecInfo.DLLPlantReason + "Imports SetDLLDirectory ";
                }

                if (DoesImport(binInfo, "SetDefaultDllDirectories", false, SecInfo)){
                    SecInfo.DLLPlantReason = SecInfo.DLLPlantReason + "Imports SetDefaultDllDirectories ";
                }

                if (DoesImport(binInfo, "AddDllDirectory", false, SecInfo)){
                    SecInfo.DLLPlantReason = SecInfo.DLLPlantReason + "Imports AddDllDirectory ";
                }
                return true;
            }

            if (DoesImportviaLoadLibrary(binInfo, "SetDLLDirectory", SecInfo) || DoesImportviaLoadLibrary(binInfo, "SetDefaultDllDirectories", SecInfo) || DoesImportviaLoadLibrary(binInfo, "AddDllDirectory", SecInfo))
            {

                if (DoesImport(binInfo, "SetDLLDirectory", false, SecInfo))
                {
                    SecInfo.DLLPlantReason = SecInfo.DLLPlantReason + "Imports via LoadLibrary SetDLLDirectory ";
                }

                if (DoesImport(binInfo, "SetDefaultDllDirectories", false, SecInfo))
                {
                    SecInfo.DLLPlantReason = SecInfo.DLLPlantReason + "Imports via LoadLibrary SetDefaultDllDirectories ";
                }

                if (DoesImport(binInfo, "AddDllDirectory", false, SecInfo))
                {
                    SecInfo.DLLPlantReason = SecInfo.DLLPlantReason + "Imports via LoadLibrary AddDllDirectory ";
                }
                return true;
            }

            return false;
        }

        public string DLLPlantingReason(PEProp binInfo, SecurityInfo SecInfo)
        {
            string strDLLPlantReason = "";

            if (DoesImport(binInfo, "SetDLLDirectory", false, SecInfo) || DoesImport(binInfo, "SetDefaultDllDirectories", false, SecInfo) || DoesImport(binInfo, "AddDllDirectory", false, SecInfo))
            {
                if (DoesImport(binInfo, "SetDLLDirectory", false, SecInfo))
                {
                    strDLLPlantReason = strDLLPlantReason + "Imports SetDLLDirectory ";
                }

                if (DoesImport(binInfo, "SetDefaultDllDirectories", false, SecInfo))
                {
                    strDLLPlantReason = strDLLPlantReason + "Imports SetDefaultDllDirectories ";
                }

                if (DoesImport(binInfo, "AddDllDirectory", false, SecInfo))
                {
                    strDLLPlantReason = strDLLPlantReason + "Imports AddDllDirectory ";
                }
                
            }

            if (DoesImportviaLoadLibrary(binInfo, "SetDLLDirectory", SecInfo) || DoesImportviaLoadLibrary(binInfo, "SetDefaultDllDirectories", SecInfo) || DoesImportviaLoadLibrary(binInfo, "AddDllDirectory", SecInfo))
            {

                if (DoesImportviaLoadLibrary(binInfo, "SetDLLDirectory", SecInfo))
                {
                    strDLLPlantReason = strDLLPlantReason + "Imports via LoadLibrary SetDLLDirectory ";
                }

                if (DoesImportviaLoadLibrary(binInfo, "SetDefaultDllDirectories", SecInfo))
                {
                    strDLLPlantReason = strDLLPlantReason + "Imports via LoadLibrary SetDefaultDllDirectories ";
                }

                if (DoesImportviaLoadLibrary(binInfo, "AddDllDirectory", SecInfo))
                {
                    strDLLPlantReason = strDLLPlantReason + "Imports via LoadLibrary AddDllDirectory ";
                }
                
            }

            
            return strDLLPlantReason;
        }
        /// <summary>
        /// Checks if the the string is in the list of imports
        /// </summary>
        /// <param name="binInfo"></param>
        /// <param name="strTheOne"></param>
        /// <returns></returns>
        public bool DoesImport(PEProp binInfo, string strTheOne, bool bExact, SecurityInfo SecInfo)
        {

            foreach (string strImport in SecInfo.Imports)
            {

                if (bExact == true)
                {
                    if (strImport.ToString().Equals(strTheOne)) return true;
                }
                else
                {
                    if (strImport.ToString().Contains(strTheOne)) return true;
                }
            }

            return false;
        }

        public bool DoesImportviaLoadLibrary(PEProp binInfo, string strTheOne, SecurityInfo SecInfo)
        {
            if (DoesImport(binInfo, strTheOne, true, SecInfo)) return true;

            if (DoesImport(binInfo, "LoadLibrary", false, SecInfo) && DoesImport(binInfo, "GetProcAddress", false, SecInfo))
            {
                System.IO.FileStream fsStream = new System.IO.FileStream(binInfo.Path, System.IO.FileMode.Open, System.IO.FileAccess.Read);
                System.IO.BinaryReader brReader = new System.IO.BinaryReader(fsStream);
                Byte[] strWorkBuff = brReader.ReadBytes((Int32)fsStream.Length);
                long lngSize = brReader.BaseStream.Length;
                long lngCnt = 0;
                long lngInnerCnt = 0;
                brReader.Close();
                fsStream.Close();

                for (lngCnt = 0; lngCnt < lngSize; lngCnt++)
                {
                    for (lngInnerCnt = 0; lngInnerCnt < strTheOne.Length; lngInnerCnt++)
                    {
                        if (strWorkBuff[lngCnt + lngInnerCnt].CompareTo(Convert.ToByte(strTheOne[(int)lngInnerCnt])) == 0) break;
                    }
                    if (lngInnerCnt == strTheOne.Length)
                    {
                        return true;
                    }
                }
            }

            return false;
        }


        public bool LoadLibrary(PEProp binInfo, SecurityInfo SecInfo)
        {
            if (DoesImport(binInfo, "LoadLibrary", false, SecInfo)) return true;

            return false;
        }


        /// <summary>
        /// Checks if the binary / uses HeapSetInformation
        /// </summary>
        /// <param name="binInfo"></param>
        /// <returns></returns>
        public bool HeapSetInfo(PEProp binInfo, SecurityInfo SecInfo)
        {
            return DoesImportviaLoadLibrary(binInfo, "HeapSetInformation", SecInfo);
        }

        public bool SetDEPPolicy(PEProp binInfo, SecurityInfo SecInfo)
        {
            return DoesImportviaLoadLibrary(binInfo, "SetProcessDEPPolicy", SecInfo);
        }

        public bool EncodePointer(PEProp binInfo, SecurityInfo SecInfo)
        {
            return DoesImportviaLoadLibrary(binInfo, "EncodePointer", SecInfo);
        }

        public bool ProcessHeapExec(PEProp binInfo)
        {

            try
            {
                ImageOptionalHeader optionalHeader = binInfo.PE.OptionalHeader;
                if (optionalHeader != null)
                {
                    ushort field = (ushort)binInfo.PE.OptionalHeader.GetField(ImageOptionalHeader.Fields.DllCharacteristics);
                    if ((field & 0x400) != 0)
                    {
                        return false;
                    }
                    SafePointer rva = (SafePointer)binInfo.PE.OptionalHeader.DirectoryEntries[10].GetField(ImageDataDirectory.Fields.VirtualAddress);
                    if (rva.Address == 0)
                    {
                        return false;
                    }
                    uint DirSize = (uint)binInfo.PE.OptionalHeader.DirectoryEntries[10].GetField(ImageDataDirectory.Fields.Size);
                    ImageLoadConfigDirectory32 directory = new ImageLoadConfigDirectory32(binInfo.PE.RVA2VA(rva));
                    int FieldSize = (int)directory.GetField(ImageLoadConfigDirectory32.Fields.Size);
                    if (FieldSize < 0x48)
                    {
                        return false;
                    }
                    uint ProcHeapFlags = (uint)directory.GetField(ImageLoadConfigDirectory32.Fields.ProcessHeapFlags);

                    if ((field & 0x00040000) != 0)
                    {
                        return true;
                    }
                }
                else
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }

            return false;
        }

        public bool ForceInt(PEProp binInfo)
        {
            try
            {
                ImageOptionalHeader optionalHeader = binInfo.PE.OptionalHeader;
                if (optionalHeader != null)
                {
                    ushort field = (ushort)optionalHeader.GetField(ImageOptionalHeader.Fields.DllCharacteristics);
                    if ((field & 0x0080) != 0)
                    {
                        return true;
                    }
                    
                }
                else
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
            return false;
        }

        public string UACUIAccess(PEProp binInfo)
        {
            IntPtr hMod = LoadLibraryEx(binInfo.Path, IntPtr.Zero, 0x2);
            if(hMod != null){
                IntPtr hRes = FindResource(hMod, 1, 24);
                if (hRes != null)
                {
                    uint intSize = SizeofResource(hMod, hRes);
                    if (intSize > 0)
                    {
                        IntPtr ptrRes = LoadResource(hMod, hRes);
                        if (ptrRes != null)
                        {
                            IntPtr strMani = LockResource(ptrRes);

                            if (strMani != null)
                            {
                                string strManifest = System.Runtime.InteropServices.Marshal.PtrToStringAnsi(strMani);
                                if (strManifest != null)
                                {
                                    //Console.WriteLine(strManifest.ToString());
                                    if (strManifest.Contains("uiAccess=\"false\"") == true)
                                    {
                                        return "False";
                                    }
                                    else if (strManifest.Contains("uiAccess=\"true\"") == true)
                                    {
                                        return "True";
                                    }
                                    else if (strManifest.Contains("uiAcces") == true)
                                    {
                                        return "Present";
                                    }
                                    else
                                    {
                                        return "Error";
                                    }
                                }
                                else
                                {
                                    return "Null";
                                }
                            }
                        }
                    }
                }
            }

            return "Not found";
        }

        public string UACIntLevel(PEProp binInfo)
        {
            IntPtr hMod = LoadLibraryEx(binInfo.Path, IntPtr.Zero, 0x2);
            if (hMod != null)
            {
                IntPtr hRes = FindResource(hMod, 1, 24);
                if (hRes != null)
                {
                    uint intSize = SizeofResource(hMod, hRes);
                    if (intSize > 0)
                    {
                        IntPtr ptrRes = LoadResource(hMod, hRes);
                        if (ptrRes != null)
                        {
                            IntPtr strMani = LockResource(ptrRes);

                            if (strMani != null)
                            {
                                string strManifest = System.Runtime.InteropServices.Marshal.PtrToStringAnsi(strMani);
                                //Console.WriteLine(strManifest.ToString());
                                if (strManifest != null)
                                {
                                    if (strManifest.Contains("level=\"requireAdministrator\"") == true)
                                    {
                                        return "Administrator";
                                    }
                                    else if (strManifest.Contains("level=\"highestAvailable\"") == true)
                                    {
                                        return "Highest";
                                    }
                                    else if (strManifest.Contains("level=\"asInvoker\"") == true)
                                    {
                                        return "Invoker";
                                    }
                                    else if (strManifest.Contains("requestedExecutionLevel") == true)
                                    {
                                        return "Present";
                                    }
                                    else
                                    {
                                        return "Error";
                                    }
                                }
                                else
                                {
                                    return "Null";
                                }
                            }
                        }
                    }
                }
            }

            return "Not found";
        }

        public bool GetManifest(PEProp binInfo, SecurityInfo secInfo)
        {
            IntPtr hMod = LoadLibraryEx(binInfo.Path, IntPtr.Zero, 0x2);
            if (hMod != null)
            {
                IntPtr hRes = FindResource(hMod, 1, 24);
                if (hRes != null)
                {
                    uint intSize = SizeofResource(hMod, hRes);
                    if (intSize > 0)
                    {
                        IntPtr ptrRes = LoadResource(hMod, hRes);
                        if (ptrRes != null)
                        {
                            IntPtr strMani = LockResource(ptrRes);

                            if (strMani != null)
                            {
                                string strManifest = System.Runtime.InteropServices.Marshal.PtrToStringAnsi(strMani);

                                int intIdx = strManifest.IndexOf("¿");
                                if (intIdx != 0)
                                {
                                    secInfo.Manifest = strManifest.Substring(intIdx + 1);
                                }
                                else
                                {
                                    secInfo.Manifest = strManifest;
                                }
                                return true;
                            }

                        }
                    }
                }
            }

            return false;
        }

        public bool GS1Check(PEProp binInfo)
        {

            try
            {
                ImageOptionalHeader optionalHeader = binInfo.PE.OptionalHeader;
                if (optionalHeader != null)
                {
                    ushort field = (ushort)binInfo.PE.OptionalHeader.GetField(ImageOptionalHeader.Fields.DllCharacteristics);
                    if ((field & 0x400) != 0)
                    {
                        return false;
                    }
                    SafePointer rva = (SafePointer)binInfo.PE.OptionalHeader.DirectoryEntries[10].GetField(ImageDataDirectory.Fields.VirtualAddress);
                    if (rva.Address == 0)
                    {
                        return false;
                    }
                    uint DirSize = (uint)binInfo.PE.OptionalHeader.DirectoryEntries[10].GetField(ImageDataDirectory.Fields.Size);
                    ImageLoadConfigDirectory32 directory = new ImageLoadConfigDirectory32(binInfo.PE.RVA2VA(rva));
                    int FieldSize = (int)directory.GetField(ImageLoadConfigDirectory32.Fields.Size);
                    if (FieldSize < 0x48)
                    {
                        return false;
                    }
                    uint GSCookieLoc = (uint)directory.GetField(ImageLoadConfigDirectory32.Fields.SecurityCookie);

                    if (GSCookieLoc != 0)
                    {
                        return true;
                    }
                }
                else
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }

            return false;
        }

        public long GSCookieHunter(byte[] strWorkBuff, long lngFileSize, byte[] strGSAddr)
        {
            long	lngCnt=0;
	        long	lngNumofRefs=0;
	        long	lngStart=0;
	        long	lngFinish=0;

	        lngStart=0;
	        lngFinish=lngFileSize-5;

            try
            {
                for (lngCnt = lngStart; lngCnt <= lngFinish; lngCnt++)
                {
                    if ((strWorkBuff[lngCnt] == 0xA1) && (strWorkBuff[lngCnt + 1] == strGSAddr[0]) && (strWorkBuff[lngCnt + 2] == strGSAddr[1]) && (strWorkBuff[lngCnt + 3] == strGSAddr[2]) && (strWorkBuff[lngCnt + 4] == strGSAddr[3]))
                    {
                        lngNumofRefs++;
                    }
                }
            }
            catch
            {
                
            }

	        return lngNumofRefs;
        }

        public bool GSCheck64(PEProp binInfo)
        {
            long lngCnt;         
            System.IO.FileStream fsStream = new System.IO.FileStream(binInfo.Path, System.IO.FileMode.Open, System.IO.FileAccess.Read); 
            System.IO.BinaryReader brReader = new System.IO.BinaryReader(fsStream);
            Byte[] strWorkBuff = brReader.ReadBytes((Int32)fsStream.Length);
            long lngSize = brReader.BaseStream.Length;
            brReader.Close(); 
            fsStream.Close();

            try
            {
                for (lngCnt = 0; lngCnt < lngSize; lngCnt++)
                {
                    if ( // epilogue
                        strWorkBuff[lngCnt] == 0x75 && strWorkBuff[lngCnt + 1] == 0x11 &&
                        strWorkBuff[lngCnt + 2] == 0x48 && strWorkBuff[lngCnt + 3] == 0xc1 &&
                        strWorkBuff[lngCnt + 4] == 0xc1 && strWorkBuff[lngCnt + 5] == 0x10 &&
                        strWorkBuff[lngCnt + 6] == 0x66 && strWorkBuff[lngCnt + 7] == 0xf7 &&
                        strWorkBuff[lngCnt + 8] == 0xc1 && strWorkBuff[lngCnt + 9] == 0xff &&
                        strWorkBuff[lngCnt + 10] == 0xff && strWorkBuff[lngCnt + 11] == 0x75 &&
                        strWorkBuff[lngCnt + 12] == 0x02 && strWorkBuff[lngCnt + 13] == 0xf3 &&
                        strWorkBuff[lngCnt + 14] == 0xc3
                        )
                    {
                        return true;

                        //0  1  2  3  4  5  6
                        //48 8D 0D XX XX XX XX lea         rcx,[GS_ContextRecord (13FC630F0h)]  
                        //7  8  9  10 11 12
                        //FF 15 XX XX XX XX    call        qword ptr [__imp_RtlCaptureContext (13FC62028h)]  
                        //13    14 15 16 17 18 19
                        //48/4C 8B XX XX XX XX XX mov         rax,qword ptr [GS_ContextRecord+0F8h (13FC631E8h)]  
                        //20    21 22 23 24
                        //48/4C XX XX XX XX
                        //25 26 27
                        //45 33 C0

                    }
                    else if ( // __report_gs_failure - well part of
                      strWorkBuff[lngCnt] == 0x48 && strWorkBuff[lngCnt + 1] == 0x8D &&
                      strWorkBuff[lngCnt + 2] == 0x0D && strWorkBuff[lngCnt + 7] == 0xFF &&
                      strWorkBuff[lngCnt + 8] == 0x15 &&
                      (strWorkBuff[lngCnt + 13] == 0x48 || strWorkBuff[lngCnt + 13] == 0x4C) &&
                      strWorkBuff[lngCnt + 14] == 0x8B &&
                      (strWorkBuff[lngCnt + 20] == 0x48 || strWorkBuff[lngCnt + 20] == 0x4C) &&
                      strWorkBuff[lngCnt + 25] == 0x45 && strWorkBuff[lngCnt + 26] == 0x33 &&
                      strWorkBuff[lngCnt + 27] == 0xC0
                      )
                    {
                        return true;
                        /*
                            1  2  3  4  5  6
                            FF 15 XX XX XX XX
                            7  8  9  10 11
                            4C 8B 5C 24 38
                            12 13 14
                            4C 33 DB
                            15 16 17 18 19 20 21 22 23 24
                            48 B8 FF FF FF FF FF FF 00 00
                            25 26 27
                            4C 23 D8
                            28 29 30 31 32 33 34 35 36 37
                            48 B8 33 A2 DF 2D 99 2B 00 00
                         */


                    }
                    else if ( // ___security_init_cookie - part of
                      strWorkBuff[lngCnt] == 0xFF && strWorkBuff[lngCnt + 1] == 0x15 &&
                      strWorkBuff[lngCnt + 6] == 0x4C && strWorkBuff[lngCnt + 7] == 0x8B &&
                      strWorkBuff[lngCnt + 8] == 0x5C && strWorkBuff[lngCnt + 9] == 0x24 &&
                      strWorkBuff[lngCnt + 10] == 0x38 && strWorkBuff[lngCnt + 11] == 0x4C &&
                      strWorkBuff[lngCnt + 12] == 0x33 && strWorkBuff[lngCnt + 13] == 0xDB &&
                      strWorkBuff[lngCnt + 14] == 0x48 && strWorkBuff[lngCnt + 15] == 0xB8 &&
                      strWorkBuff[lngCnt + 16] == 0xFF && strWorkBuff[lngCnt + 17] == 0xFF &&
                      strWorkBuff[lngCnt + 18] == 0xFF && strWorkBuff[lngCnt + 19] == 0xFF &&
                      strWorkBuff[lngCnt + 20] == 0xFF && strWorkBuff[lngCnt + 21] == 0xFF &&
                      strWorkBuff[lngCnt + 22] == 0x00 && strWorkBuff[lngCnt + 23] == 0x00 &&
                      strWorkBuff[lngCnt + 24] == 0x4C && strWorkBuff[lngCnt + 25] == 0x23 &&
                      strWorkBuff[lngCnt + 26] == 0xD8 && strWorkBuff[lngCnt + 27] == 0x48 &&
                      strWorkBuff[lngCnt + 28] == 0xB8 && strWorkBuff[lngCnt + 29] == 0x33 &&
                      strWorkBuff[lngCnt + 30] == 0xA2 && strWorkBuff[lngCnt + 31] == 0xDF &&
                      strWorkBuff[lngCnt + 32] == 0x2D && strWorkBuff[lngCnt + 33] == 0x99 &&
                      strWorkBuff[lngCnt + 34] == 0x2B && strWorkBuff[lngCnt + 35] == 0x00 &&
                      strWorkBuff[lngCnt + 36] == 0x00

                  )
                    {
                        return true;
                    } else if ( // ___security_init_cookie - part of
                      strWorkBuff[lngCnt] == 0x48 && strWorkBuff[lngCnt + 1] == 0xBA &&
                      strWorkBuff[lngCnt + 2] == 0xFF && strWorkBuff[lngCnt + 3] == 0xFF &&
                      strWorkBuff[lngCnt + 4] == 0xFF && strWorkBuff[lngCnt + 5] == 0xFF &&
                      strWorkBuff[lngCnt + 6] == 0xFF && strWorkBuff[lngCnt + 7] == 0xFF &&
                      strWorkBuff[lngCnt + 8] == 0x00 && strWorkBuff[lngCnt + 9] == 0x00 &&
                      strWorkBuff[lngCnt + 10] == 0x48 && strWorkBuff[lngCnt + 11] == 0x33 &&
                      strWorkBuff[lngCnt + 12] == 0xC1 && strWorkBuff[lngCnt + 13] == 0x48 &&
                      strWorkBuff[lngCnt + 14] == 0x23 && strWorkBuff[lngCnt + 15] == 0xC2 &&
                      strWorkBuff[lngCnt + 16] == 0x48 && strWorkBuff[lngCnt + 17] == 0x89 &&
                      strWorkBuff[lngCnt + 18] == 0x01
                  )
                    {
                        return true;
                    }
                }
            }
            catch
            {
                return false;
            }
            return false;
        }

        public int GS2Check32(PEProp binInfo)
        {

            //Console.WriteLine("G32Check32 - " + binInfo.Path);
            long lngCnt;         
            int	intGS=0;
	        int	intGSFound=0;
	        int intGS03=0;
	        int intGS0508=0;
            System.IO.FileStream fsStream = new System.IO.FileStream(binInfo.Path, System.IO.FileMode.Open, System.IO.FileAccess.Read); 
            System.IO.BinaryReader brReader = new System.IO.BinaryReader(fsStream);
            Byte[] strWorkBuff = brReader.ReadBytes((Int32)fsStream.Length);
            long lngSize = brReader.BaseStream.Length;
            brReader.Close(); 
            fsStream.Close();

        //OllieCantCode:

            try
            {
                for (lngCnt = 0; lngCnt < lngSize; lngCnt++)
                {
                    // VS2003 /GS check

                    // PUSH 0000008h
                    if (strWorkBuff[lngCnt] == 0x6A)
                    {
                        if (strWorkBuff[lngCnt + 1] == 0x08)
                        {
                            // skip PUSH ????????
                            // skip call ????????
                            // AND DWORD PTR [ebp-04h],000000h
                            if (strWorkBuff[lngCnt + 12] == 0x83)
                            {
                                if (strWorkBuff[lngCnt + 13] == 0x65)
                                {
                                    if (strWorkBuff[lngCnt + 14] == 0xFC)
                                    {
                                        if (strWorkBuff[lngCnt + 15] == 0x00)
                                        {
                                            // PUSH 00000000h
                                            if (strWorkBuff[lngCnt + 16] == 0x6A)
                                            {
                                                if (strWorkBuff[lngCnt + 17] == 0x00)
                                                {
                                                    // PUSH 00000001h
                                                    if (strWorkBuff[lngCnt + 18] == 0x6A)
                                                    {
                                                        if (strWorkBuff[lngCnt + 19] == 0x01)
                                                        {
                                                            // skip CALL ???????? // this is to MSVCR71.dll!__security_error_handler
                                                            if (strWorkBuff[lngCnt + 25] == 0x59)
                                                            {
                                                                if (strWorkBuff[lngCnt + 26] == 0x59)
                                                                {
                                                                    // skip JMP ??
                                                                    // XOR EAX,EAX
                                                                    if (strWorkBuff[lngCnt + 29] == 0x33)
                                                                    {
                                                                        if (strWorkBuff[lngCnt + 30] == 0xC0)
                                                                        {
                                                                            // INC EAX
                                                                            if (strWorkBuff[lngCnt + 31] == 0x40)
                                                                            {
                                                                                // RETN
                                                                                if (strWorkBuff[lngCnt + 32] == 0xC3)
                                                                                {
                                                                                    intGS = 1;
                                                                                    intGS03 = 1;
                                                                                    //break;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // VS 2005 __security_check_cookie stub check
                    // CMP ECX, ?????
                    if (strWorkBuff[lngCnt] == 0x3B)
                    {
                        if (strWorkBuff[lngCnt + 1] == 0x0D)
                        {
                            // skip the CMP ECX, ??????
                            // but copy the address in

                            // TODO
                            // memcpy(strGSAddr, &strWorkBuff[lngCnt + 2], 4);

                            // JNZ ??
                            if (strWorkBuff[lngCnt + 6] == 0x75)
                            {
                                // TEST ECX,FFFF0000h
                                if (strWorkBuff[lngCnt + 8] == 0xF7)
                                {
                                    if (strWorkBuff[lngCnt + 9] == 0xC1)
                                    {
                                        if (strWorkBuff[lngCnt + 10] == 0x00)
                                        {
                                            if (strWorkBuff[lngCnt + 11] == 0x00)
                                            {
                                                if (strWorkBuff[lngCnt + 12] == 0xFF)
                                                {
                                                    if (strWorkBuff[lngCnt + 13] == 0xFF)
                                                    {
                                                        // JNZ ??
                                                        if (strWorkBuff[lngCnt + 14] == 0x75)
                                                        {
                                                            // RET
                                                            if (strWorkBuff[lngCnt + 16] == 0xC3)
                                                            {
                                                                intGS = 4;
                                                                intGS0508 = 1;
                                                                //break;
                                                            }
                                                            else if (strWorkBuff[lngCnt + 16] == 0xF3)
                                                            {
                                                                if (strWorkBuff[lngCnt + 17] == 0xC3)
                                                                {
                                                                    intGS = 6;
                                                                    intGS0508 = 1;
                                                                    //break;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // REP RETN
                                }
                                else if (strWorkBuff[lngCnt + 8] == 0xF3)
                                {
                                    if (strWorkBuff[lngCnt + 9] == 0xC3)
                                    {
                                        // JMP ??????
                                        if (strWorkBuff[lngCnt + 10] == 0xE9)
                                        {
                                            intGS = 3;
                                            intGS0508 = 1;
                                            //break;
                                            // ???
                                        }
                                        else
                                        {
                                            intGS = 7;
                                            intGS0508 = 1;
                                            //break;
                                        }
                                    }
                                }
                                // JMP ????????
                            }
                            else if (strWorkBuff[lngCnt + 6] == 0x0F)
                            {
                                // TEST ECX,FFFF0000h
                                if (strWorkBuff[lngCnt + 12] == 0xF7)
                                {
                                    if (strWorkBuff[lngCnt + 13] == 0xC1)
                                    {
                                        if (strWorkBuff[lngCnt + 14] == 0x00)
                                        {
                                            if (strWorkBuff[lngCnt + 15] == 0x00)
                                            {
                                                if (strWorkBuff[lngCnt + 16] == 0xFF)
                                                {
                                                    if (strWorkBuff[lngCnt + 17] == 0xFF)
                                                    {
                                                        // JNZ ????????
                                                        if (strWorkBuff[lngCnt + 18] == 0x0F)
                                                        {
                                                            intGS = 5;
                                                            intGS0508 = 1;
                                                            //break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    // REP RETN
                                }
                                else if (strWorkBuff[lngCnt + 12] == 0xF3)
                                {
                                    if (strWorkBuff[lngCnt + 13] == 0xC3)
                                    {
                                        // JMP ??????
                                        if (strWorkBuff[lngCnt + 14] == 0xE9)
                                        {
                                            intGS = 3;
                                            intGS0508 = 1;
                                            //break;
                                            // NOP
                                        }
                                        else
                                        {
                                            intGS = 7;
                                            intGS0508 = 1;
                                            //break;
                                        }
                                    }
                                    // JMP
                                }
                                else if (strWorkBuff[lngCnt + 12] == 0xE9)
                                {
                                    intGS = 8;
                                    intGS0508 = 1;
                                    //break;
                                }

                            }
                        }
                    }

                    // VS 2005 GSDriverEntry stub check
                    // MOV EDI, EDI
                    if (strWorkBuff[lngCnt] == 0x8B)
                    {
                        if (strWorkBuff[lngCnt + 1] == 0xFF)
                        {
                            // PUSH EBP
                            if (strWorkBuff[lngCnt + 2] == 0x55)
                            {
                                // MOV EBP, ESP
                                if (strWorkBuff[lngCnt + 3] == 0x8B)
                                {
                                    if (strWorkBuff[lngCnt + 4] == 0xEC)
                                    {
                                        // MOV EAX, __security_cookie
                                        if (strWorkBuff[lngCnt + 5] == 0xA1)
                                        {
                                            // TODO
                                            //memcpy(strGSAddr, &strWorkBuff[lngCnt + 6], 4);

                                            // TEST EAX, EAX
                                            if (strWorkBuff[lngCnt + 10] == 0x85)
                                            {
                                                if (strWorkBuff[lngCnt + 11] == 0xC0)
                                                {
                                                    // MOV EAX, XXXXXXXX
                                                    if (strWorkBuff[lngCnt + 12] == 0xB9)
                                                    {
                                                        // JZ ??
                                                        if (strWorkBuff[lngCnt + 17] == 0x74)
                                                        {
                                                            // CMP EAX, ECX
                                                            if (strWorkBuff[lngCnt + 19] == 0x3B)
                                                            {
                                                                if (strWorkBuff[lngCnt + 20] == 0xC1)
                                                                {
                                                                    // JNZ ??
                                                                    if (strWorkBuff[lngCnt + 21] == 0x75)
                                                                    {
                                                                        intGS = 9;
                                                                        intGS0508 = 1;
                                                                        //break;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                /*
                if(intGS==8){
                    lngTmp=0;
                    //lngTmp=GSCookieHunter(strWorkBuff,lngSize,fff);
                    if(lngTmp==0){
                        intGS=0;
                        long lngStart=lngCnt+12;
                        if(lngStart<=lngSize){
                            goto OllieCantCode;
                        }        
                    }
                }*/

            }
            catch
            {
                return 0;
            }

            if(intGS03==1 || intGS0508==1){
		        intGSFound=1;
	        } else if(intGS03==1 && intGS0508==1) {
		        intGSFound=9;
	        }

            return intGS;
        }

        public bool GS3Check(PEProp binInfo, SecurityInfo SecInfo)
        {

            foreach (string strImport in SecInfo.Imports)
            {

                if (strImport.ToString() == "_crt_debugger_hook") return true;
            }

            return false;
        }
    
        public List<String> MSCompilerVers(PEProp binInfo)
        {
            BinaryReader binReader = new BinaryReader(File.OpenRead(binInfo.Path));
            UInt32[] arraryDWORDs = new UInt32[1024];
            int intCount=0;
            int intPos = 0;
            bool bFound = false;
            UInt32 XORKey = 0;
            List<String> lstCompilers = new List<String>();

            try
            {
                if (binReader != null)
                {
                    // Find the XOR key
                    while (intCount < 1024 && intPos < binReader.BaseStream.Length)
                    {
                        arraryDWORDs[intCount] = binReader.ReadUInt32();
                        if (arraryDWORDs[intCount] == 0x68636952)
                        {
                            bFound = true;
                            //Console.WriteLine("1 - "+ intCount.ToString());
                            break;
                        }
                        intPos += sizeof(UInt32);
                        intCount++;
                    }

                    // Extract the XOR key
                    if (bFound == true)
                    {
                        XORKey = binReader.ReadUInt32();
                        intPos += sizeof(UInt32);

                        // Now find the start of the version numbers
                        int intCount2 = 0;
                        int intPos2 = 0;
                        bool bFound2 = false;
                        UInt32 intTemp = 0;
                        binReader.BaseStream.Seek(0, SeekOrigin.Begin);
                        while (intCount2 < intCount && intPos < binReader.BaseStream.Length)
                        {
                            intTemp = binReader.ReadUInt32();
                            intTemp ^= XORKey;
                            //Console.WriteLine(intCount2.ToString());

                            if (intTemp == 0x536E6144)
                            {
                                //Console.WriteLine("2 - " + intCount2.ToString());
                                bFound2 = true;
                                break;
                            }

                            intPos2 += sizeof(UInt32);
                            intCount2++;

                        }

                        if (bFound2)
                        {
                            // Now work from the start of the block until the end
                            // and decode
                            binReader.BaseStream.Seek(intPos2, SeekOrigin.Begin);
                            

                            int intPos3 = intPos2;
                            while (intPos3 < (intPos - 8))
                            {
                                //Console.WriteLine(intPos3.ToString());
                                UInt32 intVer = binReader.ReadUInt32();
                                UInt32 intTimes = binReader.ReadUInt32();
                                intPos3 += (sizeof(UInt32) * 2);
                                intVer ^= XORKey;
                                intTimes ^= XORKey;

                                intTemp ^= XORKey;

                                if ((intVer != 0x536E6144) && ((intVer != 0)))
                                {
                                    UInt32 intVerFin = 0;
                                    UInt32 intID = 0;

                                    intID = intVer >> 16;
                                    intVerFin = intVer & 0xFFFF;
      

                                    //Console.WriteLine("[] " + intVerFin.ToString() + " - " + intID.ToString() + " - " + intTimes.ToString());
                                    if (intVerFin >= 8034 && intVerFin <= 8966)
                                    {
                                        lstCompilers.Add("VS6 " + intVerFin + " - " + intTimes + " times/objects");
                                    }
                                    else if (intVerFin >= 9466 && intVerFin <= 9528)
                                    {
                                        lstCompilers.Add("VS2002 " + intVerFin + " - " + intTimes + " times/objects");
                                    }
                                    else if (intVerFin == 3077)
                                    {
                                        lstCompilers.Add("VS2003 " + intVerFin + " - " + intTimes + " times/objects");
                                    }
                                    else if (intVerFin == 4035)
                                    {
                                        lstCompilers.Add("VS2003 " + intVerFin + " - " + intTimes + " times/objects");
                                    }
                                    else if (intVerFin == 50727)
                                    {
                                        lstCompilers.Add("VS2005 SP1 " + intVerFin + " - " + intTimes + " times/objects");
                                    }
                                    else if (intVerFin == 21022)
                                    {
                                        lstCompilers.Add("VS2008 " + intVerFin + " - " + intTimes + " times/objects");
                                    }
                                    else if (intVerFin == 30729)
                                    {
                                        lstCompilers.Add("VS2008 SP1 " + intVerFin + " - " + intTimes + " times/objects");
                                    }
                                    else if (intVerFin == 30319)
                                    {
                                        lstCompilers.Add("VS2010 " + intVerFin + " - " + intTimes + " times/objects");
                                    }
                                    else if (intVerFin == 40219)
                                    {
                                        lstCompilers.Add("VS2013 " + intVerFin + " - " + intTimes + " times/objects");
                                    }
                                    else
                                    {
                                        lstCompilers.Add("Unknown " + intVerFin + " - " + intTimes + " times/objects");
                                    }


                                }
                            }

                            binReader.Close();
                            return lstCompilers;
                        }

                    }

                }
                binReader.Close();
            }
            catch
            {
                lstCompilers.Add("Error");
                return lstCompilers;
            }

            lstCompilers.Add("N/A");
            return lstCompilers;
        }

        public int MSBannedAPIs(SecurityInfo secInfo, string [] strImports)
        {
          
            StringBuilder strAPIBuild = new StringBuilder();
            string strRes = WinBinAudit.Properties.Resources.BannedAPIs;
            int intBannedCount = 0;
            StringReader srBannedAPIs = null;

            srBannedAPIs = new StringReader(strRes);
            

            string strLine = srBannedAPIs.ReadLine();
            while (strLine != null)
            {
                System.Diagnostics.Debug.WriteLine("[banned API] " + strLine);
                foreach (string strImport in strImports)
                {
                    if(strImport.ToString().Equals(strLine.ToString())){
                        strAPIBuild.AppendLine(strImport);
                        intBannedCount++;
                    }
                }

                strLine = srBannedAPIs.ReadLine();
            }

            if (intBannedCount == 0)
            {
                strAPIBuild.Append("N/A");
            }

            secInfo.MSSDLCBannedList = strAPIBuild.ToString();
            return intBannedCount;
        }

        public void GetFileSize(SecurityInfo secInfo, PEProp binInfo){
            secInfo.FileSize = binInfo.Length;
        }

        public void SigDetails(SecurityInfo secInfo, PEProp binInfo)
        {

            X509Certificate xcert = null;
            X509Certificate2 xcert2 = null;

            try {

                secInfo.SigName = "N/A";
                secInfo.SigAlgo = "N/A";
                secInfo.SigIssuer = "N/A";

                xcert = X509Certificate.CreateFromSignedFile(binInfo.Path);
                xcert2 = new X509Certificate2(xcert);
                secInfo.SigName = xcert.Subject;
                secInfo.SigAlgo = xcert.GetKeyAlgorithm();
                             
                JavaScience.EncryptTo eToo = new JavaScience.EncryptTo();


                // show never happen
                if (xcert2.HasPrivateKey == true)  MessageBox.Show(binInfo.Path + " includes a private key!", "Private key found", MessageBoxButtons.OK, MessageBoxIcon.Hand);
                                
                if(secInfo.SigAlgo.Equals("1.2.840.113549.1.1.1")){
                    secInfo.SigAlgo = xcert2.SignatureAlgorithm.FriendlyName + " / RSA " + eToo.GetCertPublicKeySize(xcert);
                } else if (secInfo.SigAlgo.Equals("2.5.8.1.1")){
                    secInfo.SigAlgo = xcert2.SignatureAlgorithm.FriendlyName + " / RSA " + eToo.GetCertPublicKeySize(xcert);
                } else if (secInfo.SigAlgo.Equals("1.2.840.10040.4.1")){
                    secInfo.SigAlgo = xcert2.SignatureAlgorithm.FriendlyName + " / DSA " + eToo.GetCertPublicKeySize(xcert);
                } else if (secInfo.SigAlgo.Equals("1.2.840.10046.2.1")){
                    secInfo.SigAlgo = xcert2.SignatureAlgorithm.FriendlyName + " / DH " + eToo.GetCertPublicKeySize(xcert);
                } else if (secInfo.SigAlgo.Equals("1.3.6.1.4.1.3029.1.2.1")){
                    secInfo.SigAlgo = xcert2.SignatureAlgorithm.FriendlyName + " / ElGamal " + eToo.GetCertPublicKeySize(xcert);
                } else if (secInfo.SigAlgo.Equals("1.3.6.1.4.1.25258.1.1")){
                    secInfo.SigAlgo = xcert2.SignatureAlgorithm.FriendlyName + " / NR " + eToo.GetCertPublicKeySize(xcert);
                } else if (secInfo.SigAlgo.Equals("1.3.6.1.4.1.25258.1.2")){
                    secInfo.SigAlgo = xcert2.SignatureAlgorithm.FriendlyName + " / ECDSA " + eToo.GetCertPublicKeySize(xcert);
                } else if (secInfo.SigAlgo.Equals("1.2.643.2.2.19")){
                    secInfo.SigAlgo = xcert2.SignatureAlgorithm.FriendlyName + " / GOST-34.10 " + eToo.GetCertPublicKeySize(xcert);
                }


                secInfo.SigIssuer = xcert.Issuer;

            } 
            catch (Exception e)
            {
                if(secInfo.SigName.Equals("") == true) secInfo.SigName = "N/A";
                if(secInfo.SigAlgo.Equals("") == true) secInfo.SigAlgo = "N/A";
                if(secInfo.SigIssuer.Equals("") == true) secInfo.SigIssuer = "N/A";
                secInfo.Error = "Signature details error " + e.Message;
            }
        }

        public bool HighEntropy(SecurityInfo secInfo, PEProp binInfo)
        {

            // Compiler version must be 17
            
            PEFile pE = binInfo.PE;
            ImageOptionalHeader optionalHeader = pE.OptionalHeader;
            ushort num = (ushort)optionalHeader.GetField(ImageOptionalHeader.Fields.DllCharacteristics);
            bool flag = (num & 32) != 0;
            ImageFileHeader fileHeader = pE.FileHeader;
            ushort num2 = (ushort)fileHeader.GetField(ImageFileHeader.Fields.Characteristics);
            bool flag2 = (num2 & 32) != 0;
            if (flag)
            {
                return false;
            }
            if (flag && flag2)
            {
                return true;
            }
            return false;
        }

    }

}
