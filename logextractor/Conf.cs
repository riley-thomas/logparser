using System;
using System.IO;
using System.Net.NetworkInformation;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using UAParser;

namespace logextractor
{
    class Conf
    {

        public bool arin = false;
        public bool browser = false;
        public bool count = false;
        public bool distinct = false;
        public bool external = false;
        public bool flagged = false;
        public bool foreign = false;
        public bool geoip = false;
        public bool no_nc = false;
        public bool outofarin = false;
        public bool onlyarin = false;
        public bool quiet = false;
        public bool ts = false;
        public bool useragent = false;
        public bool request = false;
        public bool local_access = false;
        public Nullable<DateTime> before_date;
        public Nullable<DateTime> after_date;
        public bool ignore_filedate = false;
        public bool no_wsvc = false;
        public string ip = null;
        public string ip_exclude = null;
        public string regex_outfilename = @"^\/out=";
        public string regex_datebefore = @"^\/before=";
        public string regex_dateafter = @"^\/after=";
        public string regex_ip = @"^\/ip=";
        public string regex_exclude = @"^\/exclude=";
        public string outfilename = null;
        public string status_code = null;
        public string regex_status_code = @"^\/s(tatus)?=";
        public string regex_request = @"^\/r(equest)?=";
        public string request_pattern = null;
        public bool wantshelp = false;
        public List<string> infiles = new List<string>();
        public MessageBag messageBag = new MessageBag();
        public Parser UAParser = Parser.GetDefault();

        public Conf(string[] args)
        {
            local_access = CanPing("10.19.214.112");
            foreach (string arg in args)
            {
                if (arg.StartsWith("/"))
                {
                    
                    if (arg == "/a" || arg == "/arin")
                    {
                        if(!local_access)
                        {
                            new MessageBag("error", "Unable to access Geo Server").PrintErrors();
                        }
                        arin = true;
                    }
                    else if (arg == "/b" || arg == "/browser")
                    {
                        browser = true;
                    }
                    else if (arg == "/c" || arg == "/count")
                    {
                        count = true;
                    }
                    else if (arg == "/d" || arg == "/distinct")
                    {
                        distinct = true;
                    }
                    else if (arg == "/e" || arg == "/external")
                    {
                        external = true;
                    }
                    else if (arg == "/f" || arg == "/flagged")
                    {
                        flagged = true;
                    }
                    else if (arg == "/g" || arg == "/geoip")
                    {
                        if (local_access)
                        {
                            geoip = true;
                        }
                        else
                        {
                            messageBag.AddError("Geo IP server at 10.19.214.112 is not reachable");
                        }
                    }
                    else if (arg == "/i" || arg == "/ignore")
                    {
                        ignore_filedate = true;
                    }
                    else if (arg == "/n" || arg == "/nonc")
                    {
                        no_nc = true;
                    }
                    else if (arg == "/o")
                    {
                        outofarin = true;
                    }
                    else if (arg == "/p")
                    {
                        onlyarin = true;
                    }
                    else if (arg == "/q" || arg == "/quiet")
                    {
                        quiet = true;
                    }
                    else if (arg == "/r" || arg == "/request")
                    {
                        request = true;
                    }
                    else if (arg == "/ts" || arg == "/timestamps")
                    {
                        ts = true;
                    }
                    else if (arg == "/u" || arg == "/agent")
                    {
                        useragent = true;
                    }
                    else if (arg == "/w" || arg == "/nowsvc")
                    {
                        no_wsvc = true;
                    }
                    else if (arg == "/?" || arg == "/help")
                    {
                        wantshelp = true;
                    }
                    else if (arg == "/foreign")
                    {
                        if (local_access)
                        {
                            foreign = true;
                            geoip = true;
                            external = true;
                            no_nc = true;
                        }
                        else
                        {
                            messageBag.AddError("Geo IP server at 10.19.214.112 is not reachable");
                        }
                    }
                    else if (Regex.IsMatch(arg, regex_outfilename))
                    {
                        string outpath = Regex.Replace(arg, regex_outfilename, "");
                        if (outfilename != null)
                        {
                            messageBag.AddError("Only one outfile may be specfied");
                        }
                        else
                        {
                            outfilename = outpath;
                        }
                    }
                    else if (Regex.IsMatch(arg, regex_datebefore))
                    {
                        if(before_date != null)
                        {
                            messageBag.AddError("Only one before date may be specfied");
                        }
                        else
                        {
                            string datestring = Regex.Replace(arg, regex_datebefore, "").Replace("\"", "").Trim();
                            if (Regex.IsMatch(datestring, @"[0-9]{1,2}\/[0-9]{1,2}\/[0-9]{4}"))
                            {
                                DateTime bdate;
                                if (DateTime.TryParse(datestring, out bdate))
                                {
                                    before_date = bdate;
                                    ts = true;
                                }
                                else
                                {
                                    messageBag.AddError("Invalid Date");
                                }
                            }
                            else
                            {
                                messageBag.AddError("Invalid Before Date. Try format mm/dd/yyyy");
                            }

                        }
                    }
                    else if (Regex.IsMatch(arg, regex_dateafter))
                    {
                        if (after_date != null)
                        {
                            messageBag.AddError("Only one after date may be specfied");
                        }
                        else
                        {
                            string datestring = Regex.Replace(arg, regex_dateafter, "").Replace("\"", "").Trim();
                            if (Regex.IsMatch(datestring, @"[0-9]{1,2}\/[0-9]{1,2}\/[0-9]{4}"))
                            {
                                DateTime adate;
                                if (DateTime.TryParse(datestring, out adate))
                                {
                                    after_date = adate;
                                    ts = true;
                                }
                                else
                                {
                                    messageBag.AddError("Invalid Date");
                                }
                            }
                            else
                            {
                                messageBag.AddError("Invalid After Date. Try format mm/dd/yyyy");
                            }
                        }
                    }
                    else if (Regex.IsMatch(arg, regex_ip))
                    {
                        if (ip != null)
                        {
                            messageBag.AddError("Only one IP filter may be specfied");
                        }
                        else
                        {
                            string ipstring = Regex.Replace(arg, regex_ip, "").Replace("\"", "").Trim();
                            if (Regex.IsMatch(ipstring, @"^\d{1,3}(\.\d{1,3}){1,3}$"))
                            {
                                ip = ipstring;
                            }
                            else
                            {
                                messageBag.AddError("Invalid IP Format.");
                            }
                        }
                    }
                    else if (Regex.IsMatch(arg, regex_exclude))
                    {
                        if (ip_exclude != null)
                        {
                            messageBag.AddError("Only one excluded IP may be specfied");
                        }
                        else
                        {
                            string ipstring = Regex.Replace(arg, regex_exclude, "").Replace("\"", "").Trim();
                            if (Regex.IsMatch(ipstring, @"^\d{1,3}(\.\d{1,3}){1,3}$"))
                            {
                                ip_exclude = ipstring;
                            }
                            else
                            {
                                messageBag.AddError("Invalid Exclude IP Format.");
                            }
                        }
                    }
                    else if (Regex.IsMatch(arg, regex_status_code))
                    {
                        if (status_code != null)
                        {
                            messageBag.AddError("Only one HTTP Status Code may be specified");
                        }
                        else
                        {
                            string status_code_string = Regex.Replace(arg, regex_status_code, "").Replace("\"", "").Trim();
                            if (Regex.IsMatch(status_code_string, @"^(2|3|4|5)(\d{1,2})?$"))
                            {
                                status_code = status_code_string;
                            }
                            else
                            {
                                messageBag.AddError("Invalid status code.");
                            }
                        }
                    }
                    else if (Regex.IsMatch(arg, regex_request))
                    {
                        if (request_pattern != null)
                        {
                            messageBag.AddError("Only one request pattern may be specified");
                        }
                        else
                        {
                            request = true;
                            request_pattern = Regex.Replace(arg, regex_request, "").Replace("\"", "").Trim();
                            try
                            {
                                bool testpattern = Regex.IsMatch("randomstring", request_pattern);
                            }
                            catch
                            {
                                messageBag.AddError("Invalid pattern: " + request_pattern);
                            }
                        }
                    }
                    else
                    {
                        messageBag.AddError("Invalid Option: " + arg);
                    }
                } 
                else
                {
                    string p = arg.Trim();
                    if (p.EndsWith(".txt") || p.EndsWith(".log"))
                    {
                        if(!infiles.Contains(p)) infiles.Add(p);
                    }
                    else
                    {
                        if (Directory.Exists(p))
                        {
                            string[] files = Directory.GetFiles(p);
                            foreach (string file in files)
                            {
                                if (file.EndsWith(".txt") || file.EndsWith(".log"))
                                {
                                    if (!infiles.Contains(file)) infiles.Add(file);
                                }
                            }
                        }
                        else
                        {
                            messageBag.AddError("Log file not found: '" + p + "'");
                        }
                    }
                }
            }
        }

        public bool ConfIsValid
        {
            get
            {
                if (onlyarin && outofarin) messageBag.AddError("Can not use /o with /p");
                if (outfilename == null && quiet) messageBag.AddError("No outfile provide and quiet mode enabled. Nothing to do");
                if (infiles.Count < 1) messageBag.AddError("No files to parse");
                if(before_date.HasValue && after_date.HasValue)
                {
                    int datecompared = DateTime.Compare(before_date.Value, after_date.Value);
                    if(datecompared < 0) messageBag.AddError("'after' date cannot be prior to 'before' date");
                    if(datecompared == 0) messageBag.AddError("'after' date cannot be the same as 'before' date");
                }
                return messageBag.errors.Count > 0 ? false : true;
            }
            set { }
        }

        public void GetHelp()
        {
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine(Environment.NewLine + " Apache Formatted Log Data Extractor Utility For Windows. JRT 2018");
            Console.ResetColor();
            string text = Environment.NewLine + " Usage:" + Environment.NewLine
                + " " + System.Reflection.Assembly.GetExecutingAssembly().GetName().Name + " /? /a /b /c /d /e /f /g /i /n (/o|/p) /q /r(={r}) /ts /u /w /before={d} /after={d} /ip={n} /status={n} /exclude={n} /foreign /out={file} path"
                + Environment.NewLine + Environment.NewLine
                + "\t\t[ /? | /help ]\t\t\t Show this help" + Environment.NewLine
                + "\t\t[ /a | /arin ]\t\t\t Attempt to get org name from ARIN" + Environment.NewLine
                + "\t\t[ /b | /browser ]\t\t Parse browser info" + Environment.NewLine
                + "\t\t[ /c | /count ]\t\t\t Count instances of IP" + Environment.NewLine
                + "\t\t[ /d | /distinct ]\t\t Include only distinct IP and Agent combos" + Environment.NewLine
                + "\t\t[ /e | /external ]\t\t Include only external IP entries" + Environment.NewLine
                + "\t\t[ /f | /flagged ]\t\t Include only flagged entries" + Environment.NewLine
                + "\t\t[ /g | /geoip ]\t\t\t Attempt to get geoip using 10.19.214.112" + Environment.NewLine
                + "\t\t[ /i | /ignore ]\t\t Ignore filedate with before/after option" + Environment.NewLine
                + "\t\t[ /n | /nonc ]\t\t\t Exclude NC IPs" + Environment.NewLine
                + "\t\t[ /o ]\t\t\t\t Only Non-ARIN IP space" + Environment.NewLine
                + "\t\t[ /p ]\t\t\t\t Only ARIN IP space" + Environment.NewLine
                + "\t\t[ /q | /quiet ]\t\t\t Suppress output to screen" + Environment.NewLine
                + "\t\t[ /r | /request={expr} ]\t Include HTTP request (only matching pattern if specified)" + Environment.NewLine
                + "\t\t[ /s | /status={code} ]\t\t Include only logs with specified status" + Environment.NewLine
                + "\t\t[ /ts | /timestamps ]\t\t Include timestamps when non-distinct output" + Environment.NewLine
                + "\t\t[ /u | /agent ]\t\t\t Include user agent if present" + Environment.NewLine
                + "\t\t[ /w | /nowsvc ]\t\t Exclude web service requests" + Environment.NewLine
                + "\t\t[ /before={mm/dd/yyyy} ]\t Include only logs dated before date" + Environment.NewLine
                + "\t\t[ /after={mm/dd/yyyy} ]\t\t Include only logs dated on or after date" + Environment.NewLine
                + "\t\t[ /ip={address} ]\t\t Include only logs from specified IP" + Environment.NewLine
                + "\t\t[ /exclude={address} ]\t\t Exclude logs with specified IP " + Environment.NewLine
                + "\t\t[ /foreign ]\t\t\t Include only Non-US GeoIP'd entries " + Environment.NewLine
                + "\t\t[ /out={path} ]\t\t\t Export results to text file" + Environment.NewLine
                + "\t\tpath\t\t\t\t Directory containing txt or log files and/or specific log file path(s)";
            Console.WriteLine(text);
        }

        protected bool CanPing(string host)
        {
            try {
                Ping ping = new Ping();
                PingReply reply = ping.Send(host, 1000);
                if(reply.Status == IPStatus.Success) return true;
            }
            catch (Exception e) { }
            return false;
        }
    }
}
