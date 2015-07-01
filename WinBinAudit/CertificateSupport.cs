//
// Based in part on http://www.jensign.com/JavaScience/dotnet/DecodeCertKey/source/DecodeCertKey.txt
//
using System;
using System.IO;
using System.Text;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;

namespace JavaScience
{

    //--- P/Invoke CryptoAPI wrapper classes -----
    public class Win32
    {

        [DllImport("crypt32.dll")]
        public static extern bool CryptDecodeObject(
        uint CertEncodingType,
        uint lpszStructType,
        byte[] pbEncoded,
        uint cbEncoded,
        uint flags,
        [In, Out] byte[] pvStructInfo,
        ref uint cbStructInfo);


        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern IntPtr CertFindCertificateInStore(
        IntPtr hCertStore,
        uint dwCertEncodingType,
        uint dwFindFlags,
        uint dwFindType,
        [In, MarshalAs(UnmanagedType.LPWStr)]String pszFindString,
        IntPtr pPrevCertCntxt);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertFreeCertificateContext(
        IntPtr hCertStore);


        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)] //overloaded
        public static extern IntPtr CertOpenStore(
        [MarshalAs(UnmanagedType.LPStr)] String storeProvider,
        uint dwMsgAndCertEncodingType,
        IntPtr hCryptProv,
        uint dwFlags,
        String cchNameString);


        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertCloseStore(
        IntPtr hCertStore,
        uint dwFlags);

    }


    [StructLayout(LayoutKind.Sequential)]
    public struct PUBKEYBLOBHEADERS
    {
        public byte bType;	//BLOBHEADER
        public byte bVersion;	//BLOBHEADER
        public short reserved;	//BLOBHEADER
        public uint aiKeyAlg;	//BLOBHEADER
        public uint magic;	//RSAPUBKEY
        public uint bitlen;	//RSAPUBKEY
        public uint pubexp;	//RSAPUBKEY
    }


    public class EncryptTo
    {

        const uint CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000;
        const uint CERT_STORE_READONLY_FLAG = 0x00008000;
        const uint CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000;
        const uint CERT_FIND_SUBJECT_STR = 0x00080007;
        const uint X509_ASN_ENCODING = 0x00000001;
        const uint PKCS_7_ASN_ENCODING = 0x00010000;
        const uint RSA_CSP_PUBLICKEYBLOB = 19;
        const int AT_KEYEXCHANGE = 1;  //keyspec values
        const int AT_SIGNATURE = 2;
        static uint ENCODING_TYPE = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;

        //private X509Certificate recipcert;
        private byte[] certkeymodulus;
        private byte[] certkeyexponent;
        private uint certkeysize;
        private bool verbose = false;



        //--- Search for first matching certificate in CryptoAPI cert stores ---
        private X509Certificate GetRecipientStoreCert(String searchstr)
        {
            X509Certificate cert = null;
            IntPtr hSysStore = IntPtr.Zero;
            IntPtr hCertCntxt = IntPtr.Zero;
            string[] searchstores = { "ADDRESSBOOK", "MY" };

            uint openflags = CERT_SYSTEM_STORE_CURRENT_USER |
                     CERT_STORE_READONLY_FLAG |
                     CERT_STORE_OPEN_EXISTING_FLAG;

            foreach (String store in searchstores)
            {
                hSysStore = Win32.CertOpenStore("System", ENCODING_TYPE, IntPtr.Zero, openflags, store);
                if (hSysStore == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to open system store {0}", store);
                    continue;
                }
                hCertCntxt = Win32.CertFindCertificateInStore(
                   hSysStore,
                   ENCODING_TYPE,
                   0,
                   CERT_FIND_SUBJECT_STR,
                   searchstr,
                   IntPtr.Zero);

                if (hCertCntxt != IntPtr.Zero)
                {  //use certcontext from managed code
                    cert = new X509Certificate(hCertCntxt);
                    Console.WriteLine("\nFound certificate in {0} store with SubjectName string \"{1}\"", store, searchstr);
                    Console.WriteLine("SubjectName:\t{0}", cert.Subject);
                    break;
                }
            } // end foreach

            //-------  Clean Up  -----------
            if (hCertCntxt != IntPtr.Zero)
                Win32.CertFreeCertificateContext(hCertCntxt);
            if (hSysStore != IntPtr.Zero)
                Win32.CertCloseStore(hSysStore, 0);
            return cert;
        }



        //--- Get X509Certificate from binary DER or b64 cert file ---
        //--- try reading as binary DER first; if error, try b64 ---
        private X509Certificate GetRecipientFileCert(String certfile)
        {
            X509Certificate cert = null;
            try
            {
                cert = X509Certificate.CreateFromCertFile(certfile);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                StreamReader sr = File.OpenText(certfile);
                String filestr = sr.ReadToEnd();
                sr.Close();
                StringBuilder sb = new StringBuilder(filestr);
                sb.Replace("-----BEGIN CERTIFICATE-----", "");
                sb.Replace("-----END CERTIFICATE-----", "");
                //Decode 
                try
                {        //see if the file is a valid Base64 encoded cert
                    byte[] certBytes = Convert.FromBase64String(sb.ToString());
                    cert = new X509Certificate(certBytes);
                }
                catch (System.FormatException)
                {
                    Console.WriteLine("Not valid binary DER or b64 X509 certificate");
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    Console.WriteLine("Not valid binary DER or b64 X509 certificate");
                }
            }
            if (cert != null)
            {
                Console.WriteLine("{0} is a valid certificate file", certfile);
                Console.WriteLine("SubjectName:\t{0}", cert.Subject);
            }
            return cert;
        }


        public uint GetCertPublicKeySize(X509Certificate cert)
        {
            byte[] publickeyblob;
            byte[] encodedpubkey = cert.GetPublicKey(); //asn.1 encoded public key

            uint blobbytes = 0;
            if (verbose)
            {
                Console.WriteLine();
                showBytes("Encoded publickey", encodedpubkey);
                Console.WriteLine();
            }
            if (Win32.CryptDecodeObject(ENCODING_TYPE, RSA_CSP_PUBLICKEYBLOB, encodedpubkey, (uint)encodedpubkey.Length, 0, null, ref blobbytes))
            {
                publickeyblob = new byte[blobbytes];
                if (Win32.CryptDecodeObject(ENCODING_TYPE, RSA_CSP_PUBLICKEYBLOB, encodedpubkey, (uint)encodedpubkey.Length, 0, publickeyblob, ref blobbytes))
                    if (verbose)
                        showBytes("CryptoAPI publickeyblob", publickeyblob);
            }
            else
            {
                Console.WriteLine("Couldn't decode publickeyblob from certificate publickey");
                return 0;
            }

            PUBKEYBLOBHEADERS pkheaders = new PUBKEYBLOBHEADERS();
            int headerslength = Marshal.SizeOf(pkheaders);
            IntPtr buffer = Marshal.AllocHGlobal(headerslength);
            Marshal.Copy(publickeyblob, 0, buffer, headerslength);
            pkheaders = (PUBKEYBLOBHEADERS)Marshal.PtrToStructure(buffer, typeof(PUBKEYBLOBHEADERS));
            Marshal.FreeHGlobal(buffer);

            if (verbose)
            {
                Console.WriteLine("\n ---- PUBLICKEYBLOB headers ------");
                Console.WriteLine("  btype     {0}", pkheaders.bType);
                Console.WriteLine("  bversion  {0}", pkheaders.bVersion);
                Console.WriteLine("  reserved  {0}", pkheaders.reserved);
                Console.WriteLine("  aiKeyAlg  0x{0:x8}", pkheaders.aiKeyAlg);
                String magicstring = (new ASCIIEncoding()).GetString(BitConverter.GetBytes(pkheaders.magic));
                Console.WriteLine("  magic     0x{0:x8}     '{1}'", pkheaders.magic, magicstring);
                Console.WriteLine("  bitlen    {0}", pkheaders.bitlen);
                Console.WriteLine("  pubexp    {0}", pkheaders.pubexp);
                Console.WriteLine(" --------------------------------");
            }
            //-----  Get public key size in bits -------------
            this.certkeysize = pkheaders.bitlen;

            return this.certkeysize;

        }

        //----- decode public key and extract modulus and exponent ----
        private bool GetCertPublicKey(X509Certificate cert)
        {
            byte[] publickeyblob;
            byte[] encodedpubkey = cert.GetPublicKey(); //asn.1 encoded public key

            uint blobbytes = 0;
            if (verbose)
            {
                Console.WriteLine();
                showBytes("Encoded publickey", encodedpubkey);
                Console.WriteLine();
            }
            if (Win32.CryptDecodeObject(ENCODING_TYPE, RSA_CSP_PUBLICKEYBLOB, encodedpubkey, (uint)encodedpubkey.Length, 0, null, ref blobbytes))
            {
                publickeyblob = new byte[blobbytes];
                if (Win32.CryptDecodeObject(ENCODING_TYPE, RSA_CSP_PUBLICKEYBLOB, encodedpubkey, (uint)encodedpubkey.Length, 0, publickeyblob, ref blobbytes))
                    if (verbose)
                        showBytes("CryptoAPI publickeyblob", publickeyblob);
            }
            else
            {
                Console.WriteLine("Couldn't decode publickeyblob from certificate publickey");
                return false;
            }

            PUBKEYBLOBHEADERS pkheaders = new PUBKEYBLOBHEADERS();
            int headerslength = Marshal.SizeOf(pkheaders);
            IntPtr buffer = Marshal.AllocHGlobal(headerslength);
            Marshal.Copy(publickeyblob, 0, buffer, headerslength);
            pkheaders = (PUBKEYBLOBHEADERS)Marshal.PtrToStructure(buffer, typeof(PUBKEYBLOBHEADERS));
            Marshal.FreeHGlobal(buffer);

            if (verbose)
            {
                Console.WriteLine("\n ---- PUBLICKEYBLOB headers ------");
                Console.WriteLine("  btype     {0}", pkheaders.bType);
                Console.WriteLine("  bversion  {0}", pkheaders.bVersion);
                Console.WriteLine("  reserved  {0}", pkheaders.reserved);
                Console.WriteLine("  aiKeyAlg  0x{0:x8}", pkheaders.aiKeyAlg);
                String magicstring = (new ASCIIEncoding()).GetString(BitConverter.GetBytes(pkheaders.magic));
                Console.WriteLine("  magic     0x{0:x8}     '{1}'", pkheaders.magic, magicstring);
                Console.WriteLine("  bitlen    {0}", pkheaders.bitlen);
                Console.WriteLine("  pubexp    {0}", pkheaders.pubexp);
                Console.WriteLine(" --------------------------------");
            }
            //-----  Get public key size in bits -------------
            this.certkeysize = pkheaders.bitlen;

            //-----  Get public exponent -------------
            byte[] exponent = BitConverter.GetBytes(pkheaders.pubexp); //little-endian ordered
            Array.Reverse(exponent);    //convert to big-endian order
            this.certkeyexponent = exponent;
            if (verbose)
                showBytes("\nPublic key exponent (big-endian order):", exponent);

            //-----  Get modulus  -------------
            int modulusbytes = (int)pkheaders.bitlen / 8;
            byte[] modulus = new byte[modulusbytes];
            try
            {
                Array.Copy(publickeyblob, headerslength, modulus, 0, modulusbytes);
                Array.Reverse(modulus);   //convert from little to big-endian ordering.
                this.certkeymodulus = modulus;
                if (verbose)
                    showBytes("\nPublic key modulus  (big-endian order):", modulus);
            }
            catch (Exception)
            {
                Console.WriteLine("Problem getting modulus from publickeyblob");
                return false;
            }
            return true;
        }


        //--- Encrypt the content file and encrypt the key and IV for exchange ---
        private bool TripleDESEncrypt(String content, String encContent, String encKeyfile, String encIVfile)
        {
            FileStream fin = new FileStream(content, FileMode.Open, FileAccess.Read);
            FileStream fout = new FileStream(encContent, FileMode.OpenOrCreate, FileAccess.Write);

            byte[] buff = new byte[1000]; //encryption buffer.
            int lenread;

            byte[] encdata;

            try
            {
                TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
                CryptoStream encStream = new CryptoStream(fout, tdes.CreateEncryptor(), CryptoStreamMode.Write);

                Console.WriteLine("\nEncrypting content ... ");

                //do the encryption ...
                while ((lenread = fin.Read(buff, 0, 1000)) > 0)
                    encStream.Write(buff, 0, lenread);
                encStream.Close();

                //--- Encrypt the 3DES key and IV to output files ---
                //-----  bug in FCL 1.0 which changes passes array; therefore pass in copy only --------
                Console.WriteLine("Encrypting 3DES Key and IV ... ");
                encdata = DoRSAEncrypt(tdes.Key, (byte[])certkeymodulus.Clone(), (byte[])certkeyexponent.Clone());
                if (encdata == null)
                    return false;
                this.PutFileBytes(encKeyfile, encdata, encdata.Length);
                encdata = DoRSAEncrypt(tdes.IV, (byte[])certkeymodulus.Clone(), (byte[])certkeyexponent.Clone());
                if (encdata == null)
                    return false;
                this.PutFileBytes(encIVfile, encdata, encdata.Length);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }



        private byte[] DoRSAEncrypt(byte[] keydata, byte[] modulus, byte[] exponent)
        {
            if (keydata == null || modulus == null || exponent == null)
                return null;
            byte[] protectedkey = null;
            try
            {
                //Initialize RSAKeyInfo with public parameters
                RSAParameters RSAKeyInfo = new RSAParameters();
                RSAKeyInfo.Modulus = modulus;
                RSAKeyInfo.Exponent = exponent;

                //Initialize RSACryptoServiceProvider
                RSACryptoServiceProvider oRSA = new RSACryptoServiceProvider();
                oRSA.ImportParameters(RSAKeyInfo);
                protectedkey = oRSA.Encrypt(keydata, false);
            }

            catch (CryptographicException)
            {
                return null;
            }
            return protectedkey;
        }



        private static void usage()
        {
            Console.WriteLine("\nUsage:\nEncryptTo.exe [ContentFile] [outFile] [outKeyfile] [outIVfile]");
        }


        private void PutFileBytes(String outfile, byte[] data, int bytes)
        {
            FileStream fs = null;
            if (bytes > data.Length)
            {
                Console.WriteLine("Too many bytes");
                return;
            }
            try
            {
                fs = new FileStream(outfile, FileMode.Create);
                fs.Write(data, 0, bytes);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            finally
            {
                fs.Close();
            }
        }


        private static void showBytes(String info, byte[] data)
        {
            Console.WriteLine("{0}  [{1} bytes]", info, data.Length);
            for (int i = 1; i <= data.Length; i++)
            {
                Console.Write("{0:X2}  ", data[i - 1]);
                if (i % 16 == 0)
                    Console.WriteLine();
            }
            Console.WriteLine();
        }

    }
}