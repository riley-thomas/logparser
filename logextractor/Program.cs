using System;
using System.Collections.Generic;

namespace logextractor
{
    class Program
    {
        static void Main(string[] args)
        {
            Conf conf = new Conf(args);
            LogFile log = new LogFile();
            Dictionary<int, string> infiles = new Dictionary<int, string>();
            if (conf.wantshelp || args.Length < 1)
            {
                conf.GetHelp();
                return;
            }
            
            if(!conf.ConfIsValid)
            {
                conf.messageBag.PrintErrors();
                return;
            }

            if (conf.outfilename != null)
            {
                log.logpath = conf.outfilename;
                if (!log.IsAccessible())
                {
                    new MessageBag("error", "Invalid Outfile:" + log.logpath).PrintErrors();
                    return;
                }
            }
            int parsecount = 0;
            LogParser parser = new LogParser(conf);
            List<LogItem> logitems = parser.GetLines();
            Dictionary<string, string> ipaddresses = new Dictionary<string, string>();
            Dictionary<string, Geoip> geodata = new Dictionary<string, Geoip>();
            Dictionary<string, int> counts = new Dictionary<string, int>();
            if (logitems.Count > 0)
            {
                if (conf.count == true)
                {
                    foreach (LogItem logitem in logitems)
                    {
                        if (counts.ContainsKey(logitem.ip)) { counts[logitem.ip]++; } else { counts.Add(logitem.ip, 1); }
                    }         
                }
                foreach (LogItem logitem in logitems)
                {
                    string ipinfo = null;
                    string geoinfo = null;
                    string ipcount = null;
                    string country_code = null;
                    if (logitem.HasPublicIp)
                    {
                        if (conf.arin == true)
                        {
                            if (ipaddresses.ContainsKey(logitem.ip))
                            {
                                ipinfo = ipaddresses[logitem.ip];
                            }
                            else
                            {
                                Rir rir = new Rir(logitem.ip, conf.local_access);
                                ipinfo = rir.orgname+(rir.registry != "ARIN" ? " ("+rir.registry+")" : "");
                                ipaddresses.Add(logitem.ip, ipinfo);
                            }
                        }
                        if (conf.geoip == true)
                        {
                            if (geodata.ContainsKey(logitem.ip))
                            {
                                geoinfo = geodata[logitem.ip].DataString();
                                country_code = geodata[logitem.ip].country_code;
                            }
                            else
                            {
                                Geoip geo = new Geoip(logitem.ip);
                                geodata.Add(logitem.ip, geo);
                                geoinfo = geo.DataString();
                                country_code = geo.country_code;
                            }
                        }
                        if(conf.count == true)
                        {
                            ipcount = counts.ContainsKey(logitem.ip) ? counts[logitem.ip].ToString() : null;
                        }
                    }
                    if (conf.foreign)
                    {
                        if(country_code == null || country_code == "US") continue;
                    }
                    string s = null;
                    try
                    {
                        s += logitem.ip
                           + (conf.ts ? tab(logitem.LogTimestamp.ToString()) : "")
                           + (conf.request ? tab(logitem.request) : "")
                           + (conf.request || conf.status_code != null ? tab(logitem.status_code) : "")
                           + (conf.useragent ? tab(logitem.agent) : "")
                           + (conf.geoip ? tab(country_code) + tab(geoinfo) : "")
                           + (conf.arin ? tab(ipinfo) : "")        
                           + (conf.count ? tab(ipcount) : "");
                        if (conf.browser)
                        {
                            if (logitem.useragent.client != null)
                            {
                                s += tab(logitem.useragent.client.OS.Family)
                                    + tab(logitem.useragent.client.OS.Major)
                                    + tab(logitem.useragent.client.OS.Minor)
                                    + tab(logitem.useragent.client.UA.Family)
                                    + tab(logitem.useragent.client.UA.Major);
                            }
                            else
                            {
                                s += "\t\t\t\t\t";
                            }
                        }
                        if (logitem.flagged) s += tab("FLAG");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message+Environment.NewLine+e.StackTrace);
                        return;
                    }
                    if (s.Length > 0)
                    {
                        if (conf.quiet == false) Console.WriteLine(s);
                        if (conf.outfilename != null) log.LogLine(s);
                    }
                    parsecount++;
                }
            }
            new MessageBag("message", parsecount + " Log Items Extracted").PrintMessages();
            if(conf.outfilename != null && logitems.Count > 0) System.Diagnostics.Process.Start(conf.outfilename);
            return;
        }

        protected static string tab(string s)
        {
            return "\t" + s;
        }

    }

}
