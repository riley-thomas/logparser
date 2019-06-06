using System;
using System.IO;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace logextractor
{
    class LogParser
    {
        protected Conf conf;
        protected string regex_ip = @"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b";
        protected string regex_agent = @" ""[^""]+""$";
        protected string regex_ts = @"\[\d{2} ?\/ ?(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ?\/ ?20(1|2)\d{1}:\d{2}:\d{2}:\d{2} ?-? ?\d{4}\]";
        protected string regex_request = @"""(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)?.* HTTP\/1\.1""";
        protected string regex_flagged = @"cgi-bin|\.mscgi|\.nasl|\.php|\.pl|\.cgi|\.asp|\.aspx|\.exe|\.dll|\.ini|muieblackcat|wls-wsat";
        protected string regex_http_code = @"HTTP\/1\.1"" [0-9]{3}";

        public LogParser(Conf argConf)
        {
            conf = argConf;
        }

        public List<LogItem> GetLines()
        {
            List<LogItem> logitems = new List<LogItem>();
            List<string> catalog = new List<string>();
            foreach (string item in conf.infiles)
            {
                if (File.Exists(item))
                {
                    if((conf.before_date != null || conf.after_date != null) && conf.ignore_filedate == false)
                    {
                        FileInfo fileinfo = new FileInfo(item);
                        if (conf.after_date != null)
                        {
                            if (fileinfo.LastWriteTime.CompareTo(conf.after_date) < 0) continue;
                        }
                    }
                    try
                    {
                        foreach (string line in File.ReadLines(item))
                        {
                            if(line.Length > 7)
                            {
                                if (conf.no_wsvc && line.Contains("/eh-webservices/endpoints")) continue;
                                string status_code = GetHttpCode(line);
                                if (conf.status_code != null)
                                {
                                    if (status_code == null || !status_code.StartsWith(conf.status_code)) continue;
                                }
                                string ip = GetIpAddress(line);
                                if (ip == null) continue;
                                if (!Regex.IsMatch(ip, @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")) continue;
                                if (conf.no_nc && IsNc(ip)) continue;
                                if (conf.ip_exclude != null && ip.StartsWith(conf.ip_exclude)) continue;
                                if (conf.ip != null && !ip.StartsWith(conf.ip)) continue;
                                if ((conf.external || conf.onlyarin || conf.outofarin) && (ip.StartsWith("10.") || ip.StartsWith("172.16") || ip.StartsWith("192.168."))) continue;
                                if (conf.outofarin || conf.onlyarin)
                                {
                                    string octet1 = Regex.Match(ip, @"^[0-9]{1,3}\.").Value;
                                    if (conf.outofarin && !Util.outofarin.Contains(octet1)) continue;
                                    if (conf.onlyarin && Util.outofarin.Contains(octet1)) continue;
                                }
                                string agent = conf.useragent || conf.browser ? GetAgent(line) : null;
                                string request = conf.request || conf.flagged ? GetRequest(line) : null;
                                string ts = conf.ts ? GetTs(line) : null;
                                if(conf.request_pattern != null)
                                {
                                    if (request == null) continue;
                                    if (!Regex.IsMatch(request, conf.request_pattern)) continue;
                                }
                                bool flagged = conf.flagged ? GetFlagged(request) : false;
                                if (conf.flagged == true && flagged == false) continue;
                                string catalog_key = conf.useragent || conf.browser ? ip + "_" + agent : ip;
                                if (conf.distinct && catalog.Contains(catalog_key)) continue;                 

                                LogItem logitem = new LogItem(conf, ip, agent, request, status_code, ts, flagged);
                                if ((conf.before_date != null || conf.after_date != null) && logitem.LogTimestamp == null) continue;
                                if (conf.before_date != null && logitem.LogTimestamp != null)
                                {
                                    if (!logitem.IsBefore(conf.before_date.Value)) continue;
                                }
                                if (conf.after_date != null && logitem.LogTimestamp != null)
                                {
                                    if (!logitem.IsAfter(conf.after_date.Value)) continue;
                                }
                                if (conf.distinct) catalog.Add(catalog_key);
                                logitems.Add(logitem);
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        new MessageBag("error","LogParser Error").PrintErrors();
                    }
                }
            }
            return logitems;
        }

        protected string GetIpAddress(string line)
        {
            if(line.Length > 6)
            {
                Match match = Regex.Match(line, regex_ip);
                if (match.Value.Length > 6) return match.Value.Trim();
            }            
            return null;
        }

        protected string GetRequest(string line)
        {
           Match match = Regex.Match(line, regex_request);
            if (match.Value.Length > 1) return match.Value.Trim();
           return null;
        }

        protected string GetHttpCode(string line)
        {
            Match match = Regex.Match(line, regex_http_code);
            if (match.Value.Length > 1) return match.Value.Substring(match.Value.Length - 3, 3);
            return null;
        }

        protected string GetAgent(string line)
        {
            if (line.EndsWith("\""))
            {
                Match match = Regex.Match(line, regex_agent);
                if (match.Value.Length > 2) return match.Value.Trim();
            }
            return null;
        }

        protected string GetTs(string line)
        {
            if (line.Length > 20)
            {
                Match match = Regex.Match(line, regex_ts);
                if (match.Value.Length > 20) return match.Value.Trim();
            }
            return null;
        }

        protected bool GetFlagged(string request)
        {
            if(request != null)
            {
                bool is_match = Regex.IsMatch(request, regex_flagged);
                return is_match;
            }
            return false;
        }

        protected bool IsNc(string ip)
        {
            return (ip.StartsWith("199.90.") || ip.StartsWith("204.211.") || ip.StartsWith("149.168.") || ip.StartsWith("207.4.")) ? true : false;
        }

    }
}
