using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;
using log4net;

namespace NMAP
{
    public class ParallelScanner : IPScanner
    {
        protected virtual ILog log => LogManager.GetLogger(typeof(ParallelScanner));

        public virtual Task Scan(IPAddress[] ipAddrs, int[] ports)
        {
            return Task.WhenAll(ipAddrs.Select(ipAddr => Task<IPStatus>.Run(() =>
            {
                return PingAddr(ipAddr);
            })
            .ContinueWith(prevTask =>
            {
                if (prevTask.Result == IPStatus.Success)
                {
                    var portTasks = new List<Task>();
                    foreach (var port in ports)
                    {
                        var portTask = Task.Run(() => CheckPort(ipAddr, port));
                        portTasks.Add(portTask);
                    }
                    Task.WaitAll(portTasks.ToArray()); //по идее лучше бы WhenAll
                }
            }, TaskContinuationOptions.OnlyOnRanToCompletion)).ToList());
        }

        protected IPStatus PingAddr(IPAddress ipAddr, int timeout = 3000)
        {
            log.Info($"Pinging {ipAddr}");
            using (var ping = new Ping())
            {
                var status = ping.Send(ipAddr, timeout).Status;
                log.Info($"Pinged {ipAddr}: {status}");
                return status;
            }
        }

        protected void CheckPort(IPAddress ipAddr, int port, int timeout = 3000)
        {
            using (var tcpClient = new TcpClient())
            {
                log.Info($"Checking {ipAddr}:{port}");

                var connectTask = tcpClient.Connect(ipAddr, port, timeout);
                PortStatus portStatus;
                switch (connectTask.Status)
                {
                    case TaskStatus.RanToCompletion:
                        portStatus = PortStatus.OPEN;
                        break;
                    case TaskStatus.Faulted:
                        portStatus = PortStatus.CLOSED;
                        break;
                    default:
                        portStatus = PortStatus.FILTERED;
                        break;
                }
                log.Info($"Checked {ipAddr}:{port} - {portStatus}");
            }
        }
    }
}