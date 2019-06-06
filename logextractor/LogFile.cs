using System;
using System.IO;

namespace logextractor
{
    class LogFile
    {
        public string logpath = null;

        public bool IsAccessible()
        {
            try
            {
                FileInfo fileinfo = new FileInfo(logpath);
                if (fileinfo.Directory.Exists && (fileinfo.Extension == ".txt" || fileinfo.Extension == ".log"))
                {
                    if (fileinfo.Exists)
                    {
                        if (!fileinfo.IsReadOnly) return true;    
                    }
                    else
                    {
                        if (IsDirWritable(logpath)) return true;
                    }
                }
                return false;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public void LogLine(string line)
        {
            try
            {
                File.AppendAllText(logpath, line+Environment.NewLine);
            }
            catch (Exception e)
            {
                MessageBag msgbag = new MessageBag();
                msgbag.AddError(e.Message);
                msgbag.PrintErrors();
            }
        }

        protected bool IsDirWritable(string path)
        {
            try
            {
                File.AppendAllText(path, "");
                return true;
            }
            catch (UnauthorizedAccessException e)
            {
                return false;
            }
        }
    }
}
