using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Permissions;
using System.Diagnostics;
using System.Web.Services;
using System.Web.Script.Serialization;
using System.Text;

namespace HoneytokenLogon
{
    public class CreateProcessWithHoneytoken
    {
	// Edit this to point to your Honeytoken server URL
	const string URL="http://172.16.0.100/backup";
	const string PARAM="machine";

        [Flags]
        enum LogonFlags
        {
            LOGON_NETCREDENTIALS_ONLY = 0x00000002
        }

        [Flags]
        enum CreationFlags
        {
            CREATE_SUSPENDED = 0x00000004
        }

        [StructLayout(LayoutKind.Sequential)]
        struct ProcessInfo
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct StartupInfo
        {
            public int cb;
            public string reserved1;
            public string desktop;
            public string title;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public short reserved2;
            public int reserved3;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true,
         SetLastError = true)]
        static extern bool CreateProcessWithLogonW(
            string principal,
            string authority,
            string password,
            LogonFlags logonFlags,
            string appName,
            string cmdLine,
            CreationFlags creationFlags,
            IntPtr environmentBlock,
            string currentDirectory,
            ref StartupInfo startupInfo,
            out ProcessInfo processInfo);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr h);

        private static uint CreateHoneytokenProcess(string appPath, string domain, string user,
            string password, LogonFlags lf, CreationFlags cf)
        {
            StartupInfo si = new StartupInfo();
            si.cb = Marshal.SizeOf(typeof(StartupInfo));
            ProcessInfo pi = new ProcessInfo();
            pi.dwProcessId = 0;

            if (CreateProcessWithLogonW(user, domain, password,
            lf,
            appPath, null,
            cf, IntPtr.Zero, null,
            ref si, out pi))
            {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
            else
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
            return(pi.dwProcessId);
        }

	static int Main(string[] args)
	{	
	    while(true)
	    {
   	        var httpWebRequest = (HttpWebRequest)WebRequest.Create(URL + "/?" + PARAM + "=" + System.Environment.MachineName); 
                httpWebRequest.Accept = "application/json";
                httpWebRequest.Method = "GET";

                string output = "";
               try
               {
                   var httpResponse = (HttpWebResponse)httpWebRequest.GetResponse();
                    using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
                    {
                        output = streamReader.ReadToEnd();
                    }

                    var jss = new JavaScriptSerializer();
                    var dict = jss.Deserialize<Dictionary<string,string>>(output);

                    if ((dict["d"] != "") && (dict["u"] != "") && (dict["p"] != ""))
                    {
                        Console.WriteLine("Got response from honeytoken server, caching fake credentials...");
                        uint pid = CreateHoneytokenProcess(
                           "C:\\WINDOWS\\notepad.exe", 
            		    dict["d"], dict["u"], dict["p"],
                            LogonFlags.LOGON_NETCREDENTIALS_ONLY, 
                            CreationFlags.CREATE_SUSPENDED
                        );
                        if (pid != 0)
                        {
		            Console.WriteLine("Created process {0} to cache honeytoken credentials.", pid);
		            Console.WriteLine("Sleeping for 24 hours...");
	                    System.Threading.Thread.Sleep(86400000);
		            Console.WriteLine("Cleaning up...");
                            try 
                            {
                                Process lastProcess = Process.GetProcessById((int)pid);
                                lastProcess.Kill();
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("GetProcessByID failed: '{0}'", e);
                            }
                        }
                    }
	            else
	            {
		        Console.WriteLine("Bad response from honeytoken server.");
		        Console.WriteLine("Sleeping for 60 seconds...");
	                System.Threading.Thread.Sleep(60000);
	            }
		}
                catch (Exception e)
                {
                    Console.WriteLine("HTTP request failed: '{0}'", e);
		    Console.WriteLine("Sleeping for 60 seconds...");
	            System.Threading.Thread.Sleep(60000);
                }
            } // loops forever
        }
    }
}
