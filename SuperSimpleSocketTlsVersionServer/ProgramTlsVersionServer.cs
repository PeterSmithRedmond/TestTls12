using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SuperSimpleSocketTlsVersionServer
{
    class Program
    {
        void RunOneClientConnection(string name, TcpClient client, X509Certificate cert, SslProtocols protocols)
        {
            bool doSsl = true;

            Console.WriteLine($"{name}: Connected!");
            client.NoDelay = true;
            try
            {
                //NetworkStream networkStream = client.GetStream();
                Stream stream = client.GetStream();
                string replyword = name+"-???"; // THIS WILL BE OVER-WRITTEN
                if (doSsl)
                {
                    SslStream ssl = new SslStream(stream);
                    ssl.AuthenticateAsServer(cert, false, protocols, false);
                    stream = ssl;
                    replyword = ssl.SslProtocol.ToString();
                }
                byte[] buffer = new byte[10];
                int i;
                Console.WriteLine($"{name}: READ STRING");
                string data = "";
                while (!data.Contains("\r\n") && (i = stream.Read(buffer, 0, buffer.Length)) != 0)
                {
                    data = data + System.Text.Encoding.ASCII.GetString(buffer, 0, i);
                    Console.WriteLine($"GOT PARTIAL STRING: {data}");
                }
                Console.WriteLine($"{name}: GOT STRING: {data}");

                string reply = $"HTTP/1.0 200 OK\r\n\r\n{replyword} SuperSimpleSocketTlsVersionServer TLS {protocols.ToString()}";
                Console.WriteLine($"{name}: REPLY: {reply}");
                var replyBuffer = System.Text.Encoding.ASCII.GetBytes(reply);
                stream.Write(replyBuffer, 0, replyBuffer.Length);

                stream.Close(); // closes the networkstream and the underlying sslstream as needed
                client.Close(); // closes the socket, too
            }
            catch (Exception e)
            {
                Console.WriteLine($"{name}: SOCKET ERROR: Exception: {e.Message}");
                client.Close();
            }
            Console.WriteLine($"{name}: Closing Connection");

        }

        const string AnyIP4 = "AnyIP4";
        void RunOne(string name, string listenAddress, int listenPort, SslProtocols protocols)
        {
            string serverCertFile = @"..\cert\server.cer";
            //string listenAddress = "127.0.0.1";
            //int listenPort = 41310;
            //SslProtocols protocols = SslProtocols.Ssl3;

            TcpListener server = null;
            try
            {
                X509Certificate cert = X509Certificate.CreateFromCertFile(serverCertFile);
                IPAddress local = listenAddress == AnyIP4 ? IPAddress.Any : IPAddress.Parse(listenAddress);
                server = new TcpListener(local, listenPort);
                server.Start();
                while (true)
                {
                    Console.WriteLine($"{name}: Listening!");
                    TcpClient client = server.AcceptTcpClient();
                    Task.Run(() => 
                    {
                        RunOneClientConnection(name, client, cert, protocols);
                    });
                }

            }
            catch (Exception e)
            {
                Console.WriteLine($"{name}: LISTEN ERROR: Exception: {e.Message}");
            }
            finally
            {
                server.Stop();
            }


        }
        static void Main(string[] args)
        {
            var p = new Program();
            var tasks = new Task[6];
            string address = AnyIP4; // Special constant to mean any address
            tasks[0] = Task.Run(() => p.RunOne("SSL3_ON_13339", address, 13339, SslProtocols.Ssl3));
            tasks[1] = Task.Run(() => p.RunOne("TLS10_ON_13340", address, 13340, SslProtocols.Tls));
            tasks[2] = Task.Run(() => p.RunOne("TLS11_ON_13341", address, 13341, SslProtocols.Tls11));
            tasks[3] = Task.Run(() => p.RunOne("TLS12_ON_13342", address, 13342, SslProtocols.Tls12));
            tasks[4] = Task.Run(() => p.RunOne("TLS12_11_10_ON_13343", address, 13343, SslProtocols.Tls12 | SslProtocols.Tls11   | SslProtocols.Tls));
            tasks[5] = Task.Run(() => p.RunOne("TLS12_10_ON_13344", address, 13344, SslProtocols.Tls12 | SslProtocols.Tls));
            Task.WaitAll(tasks);
        }
    }
}
