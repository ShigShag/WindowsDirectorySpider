
using System.Net;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using CommandLine;
using Securify.ShellLink;
using Newtonsoft.Json;
using System.Text;
using System.Collections.Generic;
using System.IO;
using System;
using System.Linq;
using System.IO.Compression;

namespace fileindexernet4
{
    internal class Program
    {

        public class Options
        {

            [Option('p', "path", Required = true, HelpText = "Path to scan")]
            public string Path { get; set; }

            [Option('s', "bs", Required = true, HelpText = "Business segment the scan belongs to e.g. CO")]
            public string BS { get; set; }

            [Option('u', "bu", Required = false, Default = "", HelpText = "Business unit the scan belongs to")]
            public string BU { get; set; }

            [Option('e', "extensions", Required = false, Separator = ',', HelpText = "Only consider files with these extensions. Comma separated list e.g. txt,docx,xlsx or leave empty for all files")]
            public IEnumerable<string> Extensions { get; set; }

            [Option('o', "output", Required = false, Default = "output.json", HelpText = "Output to write into")]
            public string Output { get; set; }

            [Option('c', "compress", Required = false, Default = true, HelpText = "Compress the output file")]
            public bool Compress { get; set; }
        }

        public class NetworkDrive
        {
            public NetworkDrive()
            {
                this.hostname = "";
                this.ip = "";
            }

            public NetworkDrive(string hostname, string ip)
            {
                this.hostname = hostname;
                this.ip = ip;
            }
            public string hostname { get; set; }
            public string ip { get; set; }
        }

        public class Result
        {
            public string filename { get; set; }
            public string filepath { get; set; }
            public string filetype { get; set; }
            public string fileextension { get; set; }
            public long filesize { get; set; }
            public string bs { get; set; }
            public string bu { get; set; }
            public DateTime lastmodified { get; set; }
            public bool canwrite { get; set; }
            public string hostname { get; set; }
            public string ipaddress { get; set; }
            public string driveletter { get; set; }
        }

        private static List<string> visitedFolders = new List<string>();
        private static List<string> extensions = new List<string>();
        public static Dictionary<string, NetworkDrive> hostnames = new Dictionary<string, NetworkDrive>() { { "unknown", new NetworkDrive("unknown", "0.0.0.0") } };
        public static FileStream outfile = null;
        public static string businessunit = "";
        public static string businesssegment = "";
        public static bool compress = true;
        public static SecurityIdentifier userSid = WindowsIdentity.GetCurrent().Owner;
        public static WindowsIdentity userIdentity = WindowsIdentity.GetCurrent();
        public static WindowsPrincipal userPrincipal = new WindowsPrincipal(userIdentity);
        public static FileSystemRights fileRights = FileSystemRights.Write | FileSystemRights.FullControl;



        static void Main(string[] args)
        {
            string startpath = "";
            try
            {
                ParserResult<Options> p = Parser.Default.ParseArguments<Options>(args);
                check_parameters(p);
                if (p.Errors.Any()) { return; }
                startpath = p.Value.Path;
                compress = p.Value.Compress;
            }
            catch
            {
                return;
            }


            getDriveInfo();
            check_directory(startpath);

            if (compress)
            {
                compressResults();
            }

            outfile.Close();

        }

        static bool check_parameters(ParserResult<Options> p)
        {

            bool error = false;

            Console.ForegroundColor = ConsoleColor.Red;
            if (!Directory.Exists(p.Value.Path))
            {
                error = true;
                Console.WriteLine($"The path \"{p.Value.Path}\" does not exist.");
            }

            try
            {
                outfile = new FileStream(p.Value.Output, FileMode.Create);
            }
            catch (Exception ex)
            {
                error = true;
                Console.WriteLine($"Error with output-file: \"{ex.Message}\"");
            }


            foreach (string ext in p.Value.Extensions)
            {
                if (ext.StartsWith("."))
                {
                    extensions.Add(ext.ToLower());
                }
                else
                {
                    extensions.Add("." + ext.ToLower());
                }

            }

            businesssegment = p.Value.BS;
            businessunit = p.Value.BU;

            return true;
        }

        static void check_directory(string path)
        {

            string currentDrive = "---";
            NetworkDrive currentNetworkDrive = new NetworkDrive();

            if (visitedFolders.Contains(path))
            {
                return;
            }
            visitedFolders.Add(path);

            if (!path.StartsWith(currentDrive))
            {
                currentDrive = getPathStart(path);

                if (!hostnames.ContainsKey(currentDrive))
                {
                    LookupUNC(currentDrive);
                }
                currentNetworkDrive = hostnames.ContainsKey(currentDrive) ? hostnames[currentDrive] : hostnames["unknown"];
            }

            foreach (var file in Directory.EnumerateFileSystemEntries(path, "*", SearchOption.AllDirectories))
            {
                var fileInfo = new FileInfo(file);
                Result result = new Result();

                if (fileInfo == null)
                {
                    continue;
                }

                if (fileInfo.Extension.ToLower() == ".lnk")
                {
                    try
                    {
                        Shortcut sc = Shortcut.ReadFromFile(fileInfo.FullName);
                        FileSystemInfo fsi = new FileInfo(sc.LinkTargetIDList.Path);
                        if ((fsi.Attributes & FileAttributes.Directory) == FileAttributes.Directory)
                        {
                            check_directory(fsi.FullName);
                        }
                    }
                    catch (Exception ex)
                    {
                        continue;
                    }
                }

                if ((fileInfo.Attributes & FileAttributes.Directory) == FileAttributes.Directory)
                {
                    result.filetype = "folder";
                    result.filesize = 0;
                }
                else if (fileInfo.Extension.ToLower() == ".lnk")
                {
                    result.filetype = "link";
                    result.filesize = 0;
                }
                else
                {
                    if (extensions.Count == 0 || extensions.Contains(fileInfo.Extension.ToLower()))
                    {
                        result.filetype = "file";
                        result.filesize = fileInfo.Length;
                    }
                    else
                    {
                        continue;
                    }
                }

                result.filepath = fileInfo.FullName;
                result.filename = fileInfo.Name;
                result.fileextension = fileInfo.Extension.ToLower().TrimStart('.');
                result.lastmodified = fileInfo.LastAccessTimeUtc;
                result.hostname = currentNetworkDrive.hostname;
                result.ipaddress = currentNetworkDrive.ip;
                result.driveletter = currentDrive;
                result.bs = businesssegment;
                result.bu = businessunit;

                try
                {
                    var fs = fileInfo.GetAccessControl();


                    AuthorizationRuleCollection rules = fs.GetAccessRules(true, true, userSid.GetType());
                    bool hasRights = false;
                    foreach (FileSystemAccessRule rule in rules)
                    {
                        if (userIdentity.User.Equals(rule.IdentityReference) || userPrincipal.IsInRole((SecurityIdentifier)rule.IdentityReference)){

                            if (rule.GetType() == typeof(FileSystemAccessRule))
                            {
                                if ((rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl || (rule.FileSystemRights & FileSystemRights.Write) == FileSystemRights.Write)
                                {
                                    if (rule.AccessControlType == AccessControlType.Allow)
                                    {
                                        hasRights = true;
                                    }
                                }
                            }
                        }
                    }
                    result.canwrite = hasRights;
                }
                catch
                {
                    result.canwrite = false;
                }

                byte[] data = new UTF8Encoding(true).GetBytes(JsonConvert.SerializeObject(result, Formatting.None) + "\r\n");
                outfile.Write(data, 0, data.Length);
                outfile.Flush(true);

            }
        }

        public static void compressResults()
        {
            try
            {
                outfile.Seek(0, SeekOrigin.Begin);
                FileStream destination = File.Create(outfile.Name + ".gz");
                var compressor = new GZipStream(destination, CompressionLevel.Optimal);
                outfile.CopyTo(compressor);
                compressor.Close();
            }
            catch
            {
                return;
            }
        }

        public static void getDriveInfo()
        {
            DriveInfo[] drives = DriveInfo.GetDrives();
            foreach (DriveInfo drive in drives)
            {
                if (drive.DriveType == DriveType.Network)
                {
                    {
                        //if (path.StartsWith(drive.RootDirectory.Name, true, null))
                        //{
                        string hostname = stripUNCPath(Pathing.GetUNCPath(drive.RootDirectory.FullName));
                        string Driveletter = drive.RootDirectory.Name.Substring(0, drive.RootDirectory.Name.IndexOf(@"\")).ToLower();
                        hostnames[Driveletter] = new NetworkDrive(hostname, DNSLookup(hostname));
                        //}
                    }
                }
            }
        }

        public static void LookupUNC(string path)
        {
            if (path.StartsWith(@"\\"))
            {
                string hostname = stripUNCPath(path);

                try
                {
                    IPAddress.Parse(hostname);
                    hostnames[hostname] = new NetworkDrive(hostname, hostname);
                }
                catch
                {
                    hostnames[hostname] = new NetworkDrive(hostname, DNSLookup(hostname));
                }
            }
            else
            {
                string hostname = getPathStart(path);
                hostnames[hostname] = new NetworkDrive(hostname, "0.0.0.0");
            }
        }

        public static string getPathStart(string path)
        {
            if (path.StartsWith(@"\\"))
            {
                return stripUNCPath(path);
            }
            else
            {
                if (path.Contains('\\'))
                {
                    return path.Substring(0, path.IndexOf('\\')).ToLower();
                }
                return path.ToLower();
            }
        }

        public static string stripUNCPath(string path)
        {
            if (path.StartsWith(@"\\"))
            {
                path = path.Substring(2);
            }
            return path.Split('\\')[0].ToLower();
        }

        public static string DNSLookup(string computerNameOrAddress)
        {
            try
            {
                IPHostEntry hostEntry = Dns.GetHostEntry(computerNameOrAddress);

                IPAddress[] ips = hostEntry.AddressList;
                foreach (IPAddress ip in ips)
                {
                    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        return ip.ToString();
                    }
                }
                return "0.0.0.0";
            }
            catch (Exception e)
            {
                return "0.0.0.0";
            }
        }

    }
}
