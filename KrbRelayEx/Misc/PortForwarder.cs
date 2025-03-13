using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;


namespace KrbRelayEx.Misc
{
    public class PortForwarder
    {
        private readonly int _listenPort;
        private readonly string _destinationHost;
        private readonly int _destinationPort;

        public PortForwarder(int listenPort, string destinationHost, int destinationPort)
        {
            _listenPort = listenPort;
            _destinationHost = destinationHost;
            _destinationPort = destinationPort;
        }

        public async Task StartAsync()
        {
            var listener = new TcpListener(IPAddress.Any, _listenPort);
            //Console.WriteLine($"[*] PortForwarder Listening on port {_listenPort}, forwarding to {_destinationHost}:{_destinationPort}");
            listener.Start();
            Console.WriteLine($"[*] PortForwarder Listening on port {_listenPort}, forwarding to {_destinationHost}:{_destinationPort}");

           while (true)
            {
                var client = await listener.AcceptTcpClientAsync();
                //Console.WriteLine("Source connected.", client.);
                _ = HandleConnectionAsync(client);
            }
        }

        private async Task HandleConnectionAsync(TcpClient sourceClient)
        {
            TcpClient destinationClient = new TcpClient();
            try
            {
                await destinationClient.ConnectAsync(_destinationHost, _destinationPort);
//              Console.WriteLine($"[*] PortForwarder Connected to {_destinationHost}:{_destinationPort}");

                var sourceToDestination = ForwardDataAsync(sourceClient, destinationClient, "Source -> Destination");
                var destinationToSource = ForwardDataAsync(destinationClient, sourceClient, "Destination -> Source");
                
  //            Console.WriteLine($"[*] PortForwarder Connected to {_destinationHost}:{_destinationPort}");
                // Wait until either side disconnects
                await Task.WhenAny(sourceToDestination, destinationToSource);
            }
            catch (Exception ex)
            {
                //Console.WriteLine($"[*] PortForwarder Connection error: {ex.Message}");
            }
            finally
            {
                //Console.WriteLine("[*] PortForwarder Closing connections...");
                sourceClient.Close();
                destinationClient.Close();
            }
        }
        private async Task ForwardDataAsync(TcpClient fromClient, TcpClient toClient, string direction)
        {
            try
            {
                var buffer = new byte[4096];
                using var fromStream = fromClient.GetStream();
                using var toStream = toClient.GetStream();

                while (true)
                {
                    int bytesRead = await fromStream.ReadAsync(buffer, 0, buffer.Length);
                    if (bytesRead == 0)
                    {
                        //Console.WriteLine($"{direction} connection closed.");
                        break;
                    }

                    await toStream.WriteAsync(buffer, 0, bytesRead);
                    //Console.WriteLine($"{direction}: Forwarded {bytesRead} bytes.");
                }
            }
            catch (Exception ex)
            {
                //Console.WriteLine($"{direction} connection error: {ex.Message}");
            }
        }
    }
}