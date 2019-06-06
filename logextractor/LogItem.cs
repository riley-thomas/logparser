using System;
using System.Text.RegularExpressions;
using System.Globalization;

namespace logextractor
{
    class LogItem
    {
        public string ip = null;
        public string agent = null;
        public string request = null;
        public string status_code = null;
        public string ts = null;
        public bool flagged = false;
        protected CultureInfo enUS = new CultureInfo("en-US");
        public UserAgent useragent;

        public LogItem(Conf conf, string argIP = null, string argAgent = null, string argRequest = null, string argStatus = null, string argTs = null, bool argFlagged = false)
        {
            ip = argIP?.Trim();
            agent = argAgent?.Trim();
            request = argRequest?.Trim();
            status_code = argStatus?.Trim();
            ts = argTs?.Trim();
            flagged = argFlagged;
            useragent = new UserAgent(conf, agent);

        }
        
        public void setTrimmedValue(string field, string val)
        {
            this.GetType().GetProperty(field).SetValue(this, val.Trim());
        }

        public bool HasValidIp
        {
            get
            {
                if (ip != null)
                {
                    string pattern = @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$";
                    bool valid = Regex.IsMatch(ip, pattern);
                    return valid;
                }
                return false;
            }
            set { }
        }

        public bool HasLocalIp
        {
            get
            {
                if (HasValidIp)
                {
                    if(ip.StartsWith("10.") || ip.StartsWith("172.16") || ip.StartsWith("192.168.")) return true;
                }
                return false;
            }
            set { }
        }

        public bool HasPublicIp
        {
            get
            {
                if (HasValidIp)
                {
                    if (!ip.StartsWith("10.") && !ip.StartsWith("172.16") && !ip.StartsWith("192.168.")) return true;
                }
                return false;
            }
            set { }
        }

        public Nullable<DateTime> LogTimestamp
        {
            get
            {
                if (ts != null)
                {
                    string pattern = @"\d{2} ?\/ ?(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ?\/ ?20(1|2)\d{1}:\d{2}:\d{2}:\d{2} ?-? ?\d{4}";
                    Match match = Regex.Match(ts, pattern);
                    if (match.Success)
                    {
                        DateTime date;
                        if (DateTime.TryParseExact(match.Value, "dd/MMM/yyyy:HH:mm:ss zzz", enUS, DateTimeStyles.AllowWhiteSpaces, out date)) return date;
                    }
                }
                return null;
            }
            set { }
        }

        public bool IsBefore(DateTime before)
        {
            if (LogTimestamp != null)
            {
                DateTime beforedate = new DateTime(before.Year, before.Month, before.Day, 0, 0, 0);
                DateTime comparedate = new DateTime(LogTimestamp.Value.Year, LogTimestamp.Value.Month, LogTimestamp.Value.Day, 0, 0, 0);
                int compare = DateTime.Compare(comparedate, beforedate);
                if (compare < 0) return true;
            }
            return false;
        }

        public bool IsAfter(DateTime after)
        {
            if (LogTimestamp != null)
            {
                DateTime afterdate = new DateTime(after.Year, after.Month, after.Day, 0, 0, 0);
                DateTime comparedate = new DateTime(LogTimestamp.Value.Year, LogTimestamp.Value.Month, LogTimestamp.Value.Day, 0, 0, 0);
                int compare = DateTime.Compare(comparedate, afterdate);
                if (compare >= 0) return true;
            }
            return false;
        }

    }
}
