/*
Released as open source by NCC Group Plc - http://www.nccgroup.com/
 
Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

http://www.github.com/olliencc/WinBinaryAudit/
 
Released under AGPL see LICENSE for more information
*/

using System;
using System.Collections.Generic;
using System.Text;
using ManagedMD;
using ManagedMD.Utils;
using System.Diagnostics;
using System.Security.Cryptography;
using System.IO;
using WinBinAuditv1;
using System.Collections;
using System.Drawing;

namespace WinBinAuditv1PE
{
    class PEProp
    {
        private string strPath;

        public PEProp(string path)
        {
            this.strPath = path;
        }
        
        public string Vendor
        {
            get
            {
                FileVersionInfo vendorInfo = FileVersionInfo.GetVersionInfo(System.IO.Path.GetFullPath(this.Path));
                return vendorInfo.CompanyName;
            }

        }

        public string Version
        {
            get
            {
                FileVersionInfo vendorInfo = FileVersionInfo.GetVersionInfo(System.IO.Path.GetFullPath(this.Path));
                return vendorInfo.FileVersion;
            }

        }

        public bool Kernel
        {
            get
            {
                if (this.PE.IsPEFile)
                {
                    if (this.PE.OptionalHeader == null)
                    {
                        return false;
                    }
                    foreach (string str in this.PE.Imports)
                    {
                        if ((str.StartsWith("ntoskrnl.exe", StringComparison.InvariantCultureIgnoreCase) || str.StartsWith("hal.dll", StringComparison.InvariantCultureIgnoreCase)) || (str.StartsWith("scsiport.sys", StringComparison.InvariantCultureIgnoreCase) || str.StartsWith("win32k.sys", StringComparison.InvariantCultureIgnoreCase)))
                        {
                            return true;
                        }
                    }
                }
                return false;
            }
        }

        public bool ManagedP
        {
            get
            {
                COMPEFile file = new COMPEFile(this.PE);
                if (file.Cor20Header == null)
                {
                    return false;
                }
                uint field = (uint)file.Cor20Header.GetField(ImageCor20Header.Fields.Flags);

                return ((field & 1) == 1);
            }

        }
        public bool Managed
        {
            get
            {
                try
                {
                    COMPEFile file = new COMPEFile(this.PE);
                    if (file.Cor20Header != null)
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
        }

        public bool SkipValidation
        {
            get
            {

                Assembly assembly = new Assembly(new Module(new COMPEFile(this.PE)));

                DeclaredSecurityAction[] declSecurity = assembly.DeclSecurity;

                foreach(DeclaredSecurityAction declSec in declSecurity){

                    string strXML = declSec.GetXml(assembly.Module);
                    if (strXML.Contains("SkipVerification"))
                    {
                        return true;
                    }
                }
                
                return false;
            }
        }

        public bool AllManaged
        {
            get
            {
                COMPEFile file = new COMPEFile(this.PE);
                if (file.Cor20Header == null)
                {
                    return false;
                }
                uint field = (uint)file.Cor20Header.GetField(ImageCor20Header.Fields.Flags);

                return ((field & 1) == 1);
            }
        }


        public long Length
        {
            get
            {
                  FileInfo info = new FileInfo(this.Path);
                  return info.Length;
            }
        }

        public Version LinkerVersion
        {
            get
            {
                ImageOptionalHeader optionalHeader = this.PE.OptionalHeader;
                if (optionalHeader != null)
                {
                    byte field = (byte)optionalHeader.GetField(ImageOptionalHeader.Fields.MajorLinkerVersion);
                    return new Version(field, (byte)optionalHeader.GetField(ImageOptionalHeader.Fields.MinorLinkerVersion));
                }
                return null;
            }
        }

        public MachineType Machine
        {

            get
            {
                ImageFileHeader fileHeader = this.PE.FileHeader;
                if (fileHeader != null)
                {
                    ushort field = (ushort)fileHeader.GetField(ImageFileHeader.Fields.Machine);
                    return (MachineType)field;
                }
                return MachineType.UNKNOWN;
            }
        }
        
        public string Path
        {
            get
            {
                return this.strPath;
            }
        }

        public PEFile PE
        {
            get
            {
                PEFile target;
                target = new PEFile(this.Path);
                return target;
            }
        }

        public string SHA1Hash
        {
            get
            {
                byte[] buffer = new byte[0x1000];
                SHA1 sha = SHA1.Create();
                using (FileStream stream = new FileStream(this.Path, FileMode.Open, FileAccess.Read))
                {
                    int inputCount = -1;
                    do
                    {
                        inputCount = stream.Read(buffer, 0, buffer.Length);
                        sha.TransformBlock(buffer, 0, inputCount, buffer, 0);
                    }
                    
                    while (inputCount > 0);
                        sha.TransformFinalBlock(buffer, 0, inputCount);
                }

                return BitConverter.ToString(sha.Hash).Replace("-", "");
            }
        }

        public string MD5Hash
        {
            get
            {
  
                byte[] buffer = new byte[0x1000];
                System.Security.Cryptography.MD5CryptoServiceProvider oMD5Hasher = new System.Security.Cryptography.MD5CryptoServiceProvider();

                using (FileStream stream = new FileStream(this.Path, FileMode.Open, FileAccess.Read))
                {
                    int inputCount = -1;
                    do
                    {
                        inputCount = stream.Read(buffer, 0, buffer.Length);
                        oMD5Hasher.TransformBlock(buffer, 0, inputCount, buffer, 0);
                    }
                    while (inputCount > 0);
                    
                    oMD5Hasher.TransformFinalBlock(buffer, 0, inputCount);
                }

                return BitConverter.ToString(oMD5Hasher.Hash).Replace("-", "");
            }
        }


        public Icon Fileicon
        {
            get
            {
                return Icon.ExtractAssociatedIcon(this.strPath);
            }
        }


        public bool DelayLoadImports(PEFile OpenPE)
        {
            try
            {
                if (this.m_asImports == null)
                {
                    if (((OpenPE.DirectoryEntries == null) || (OpenPE.DirectoryEntries.Length < 13)) || (OpenPE.DirectoryEntries[ImageOptionalHeader.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT] == null))
                    {
                        return false;
                    }

                    uint DirSize = (uint)OpenPE.DirectoryEntries[ImageOptionalHeader.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].GetField(ImageDataDirectory.Fields.Size);
                    if (DirSize == 0) return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        private string[] m_delayImports;
        
        public string[] DelayLoadImportFunctionsGet(PEFile OpenPE, string strFilename)
        {
            ArrayList list = new ArrayList();
            try
            {



                if (this.m_delayImports == null)
                {
                    if (((OpenPE.DirectoryEntries == null) || (OpenPE.DirectoryEntries.Length < 13)) || (OpenPE.DirectoryEntries[ImageOptionalHeader.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT] == null))
                    {
                        return null;
                    }

                    uint DirSize = (uint)OpenPE.DirectoryEntries[ImageOptionalHeader.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].GetField(ImageDataDirectory.Fields.Size);
                    if (DirSize == 0) return null;
                }


                // This gets RVA of the delay import table
                SafePointer rva = (SafePointer)OpenPE.DirectoryEntries[ImageOptionalHeader.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].GetField(ImageDataDirectory.Fields.VirtualAddress);
                if (rva.Address == 0)
                {
                    return null;
                }

                // Covert the address to the VA
                rva = OpenPE.RVA2VA(rva);


                while (((((uint)rva) != 0) && (((uint)(rva + 4)) != 0))) // IDT
                {
                    uint uAttr = (uint)(OpenPE.RVA2VA(rva));

                    SafePointer rva2 = new SafePointer();
                    rva2.Address = (int)((uint)(rva + 4)); // address of the name

                    SafePointer rva3 = new SafePointer();
                    rva3.Address = (int)((uint)(rva + 8)); // address of HMODULE

                    SafePointer rva4 = new SafePointer();
                    rva4.Address = (int)((uint)(rva + 12)); // RVA of the IAT

                    SafePointer rva5 = new SafePointer();
                    rva5.Address = (int)((uint)(rva + 16)); // RVA of the Hint table

                    // Seek and get the DLL name
                    rva2 = OpenPE.RVA2VA(rva2);
                    byte[] dataArray = new byte[1024];
                    using (FileStream fileStream = new FileStream(strFilename, FileMode.Open, FileAccess.Read))
                    {
                        fileStream.Seek(rva2.Address, SeekOrigin.Begin);
                        for (int i = 0; i < fileStream.Length; i++)
                        {
                            dataArray[i] = (byte)fileStream.ReadByte();
                            if (dataArray[i] == 0x00) break;
                        }
                    }

                    //Console.WriteLine(System.Text.Encoding.Default.GetString(dataArray));
                    list.Add(System.Text.Encoding.Default.GetString(dataArray));

                    /*
                    rva4 = OpenPE.RVA2VA(rva4);
                    int intIncr = 0;
                    if (PE.Is64Bit) intIncr = 64;
                    else intIncr = 32;
                    int intCount = 0;
                    using(FileStream fileStream = new FileStream(strFilename, FileMode.Open, FileAccess.Read))
                    {
                        fileStream.Seek(rva4.Address, SeekOrigin.Begin);
                        for(int i = 0; i < fileStream.Length; i+=intIncr){
                            Console.Write(".");
                            fileStream.Read(dataArray, 0, intIncr);
                            if (dataArray[0] == 0x00 && dataArray[1] == 0x00 && dataArray[2] == 0x00 && dataArray[3] == 0x00 && dataArray[4] == 0x00) break;
                            else intCount++;
                        
                        }
                    }
                    */
                    //Console.WriteLine("[!]" + intCount.ToString());
                    /*
                    uint field2 = 0;
                    while(
                        while(((uint)(field2)) != 0u)
                        {

                            if (OpenPE.Is64Bit == false)
                            {
                                try
                                {
                                    if (((int)((uint)(field2)) & 0x80000000) == 0x80000000) // ordinal
                                     {
                                        Console.WriteLine("Ordinal");
                                    }
                                    else
                                    {
                                        Console.WriteLine("Not Ordinal");
                                    }

                                }
                                catch (SystemException exception)
                                {
                                    throw (exception);
                                }

                                field2 += 4; // 32bit ILT
                            }
                            else
                            {
                                try
                                {
                                    if (((int)((uint)(field2+4)) & 0x80000000) == 0x80000000) // ordinal
                                    {
                                        Console.WriteLine("Ordinal");
                                    }
                                    else
                                    {
                                        Console.WriteLine("NOT Ordinal");
                                    }

                                }
                                catch (SystemException exception)
                                {
                                    throw (exception);
                                }

                                field2 += 8; // 64bit ILT
                            }
                        }
                    
                        field += 20; // IDT
                    }
                    
             

                    */
                    rva += 32; // IDT
                }

            }
            catch
            {
                return null;
                

            }

            list.Sort();
            this.m_delayImports = (string[])list.ToArray(typeof(string));
            return this.m_delayImports;
        }

        private string[] m_asImports;

        
        public string[] ImportFunctionsGet(PEFile OpenPE)
        {
            
            if (this.m_asImports == null){
                if (((OpenPE.DirectoryEntries == null) || ( OpenPE.DirectoryEntries.Length < 1)) || (OpenPE.DirectoryEntries[1] == null)){
                    return null;
                } 
            }


           ImageDataDirectory directory = OpenPE.DirectoryEntries[1];
           SafePointer field = (SafePointer)directory.GetField(ImageDataDirectory.Fields.VirtualAddress);
           ArrayList list = new ArrayList();

            
           if (field.Address != 0)
           {

               field = OpenPE.RVA2VA(field);

                while ( ((((uint)field) != 0) && (((uint)(field + 12)) != 0))) // IDT
                {
                    SafePointer rva = field;
                    rva.Address = (int)((uint)(field + 12)); // name of DLL
                    string str = (string)OpenPE.RVA2VA(rva);

                    /*
                    * Ollie
                    */
                    SafePointer rva2 = field;
                    rva2.Address = (int)((uint)(field)); // ILT RVA
                    
                    SafePointer field2;
                    field2 = OpenPE.RVA2VA(rva2); // get the ILT RVA pointed too address
                    
                    
                    while(((uint)(field2)) != 0u)
                    {

                        if (OpenPE.Is64Bit == false)
                        {
                            try
                            {
                                SafePointer rva3 = field2;

                                if (((int)((uint)(field2)) & 0x80000000) == 0x80000000) // ordinal
                                 {
                                    //Console.WriteLine("Ordinal");
                                    //list.Add(str + " - Ordinal " + Convert.ToInt16((int)((uint)(field2))) );
                                }
                                else
                                {
                                    rva3.Address = (int)((uint)(field2));

                                    string str2 = (string)(OpenPE.RVA2VA(rva3) + 2);

                                    //Console.WriteLine(str2.ToString());
                                    if (list.Contains(str2) == false)
                                    {
                                        //list.Add(str2 + "(" + str +")");
                                        list.Add(str2);
                                    }
                                }

                            }
                            catch (SystemException exception)
                            {
                                throw (exception);
                            }

                            field2 += 4; // 32bit ILT
                        }
                        else
                        {
                            try
                            {
                                SafePointer rva3 = field2;

                                if (((int)((uint)(field2+4)) & 0x80000000) == 0x80000000) // ordinal
                                {
                                    //Console.WriteLine("Ordinal");
                                    //list.Add(str + " - Ordinal " + Convert.ToInt16((int)((uint)(field2))) );
                                }
                                else
                                {
                                    rva3.Address = (int)((uint)(field2));

                                    string str2 = (string)(OpenPE.RVA2VA(rva3) + 2);

                                    //Console.WriteLine(str2.ToString());
                                    if (list.Contains(str2) == false)
                                    {
                                        //list.Add(str + " - " + str2);
                                        //list.Add(str2 + "(" + str + ")");
                                        list.Add(str2);
                                    }
                                }

                            }
                            catch (SystemException exception)
                            {
                                throw (exception);
                            }

                            field2 += 8; // 64bit ILT
                        }
                    }
                    
                    field += 20; // IDT
                    
                }
                    
            }

            list.Sort();
            this.m_asImports = (string[])list.ToArray(typeof(string));
            
            return this.m_asImports;
        }

    }


    public enum MachineType
    {
        ALPHA = 0x184,
        ALPHA64 = 0x284,
        AM33 = 0x1d3,
        AMD64 = 0x8664,
        ARM = 0x1c0,
        AXP64 = 0x284,
        CEE = 0xc0ee,
        CEF = 0xcef,
        EBC = 0xebc,
        I386 = 0x14c,
        I860 = 0x14d,
        IA64 = 0x200,
        M32R = 0x9041,
        MIPS16 = 0x266,
        MIPSFPU = 870,
        MIPSFPU16 = 0x466,
        POWERPC = 0x1f0,
        POWERPCFP = 0x1f1,
        R10000 = 360,
        R3000 = 0x162,
        R4000 = 0x166,
        SH3 = 0x1a2,
        SH3DSP = 0x1a3,
        SH3E = 420,
        SH4 = 0x1a6,
        SH5 = 0x1a8,
        THUMB = 450,
        TRICORE = 0x520,
        UNKNOWN = 0,
        WCEMIPSV2 = 0x169
    }

}
