using System;
using System.Net.Http;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.IO;


namespace logextractor
{
    class BrowsCap
    {
        private JObject j;
        private string localappdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        private bool local_access = false;
        public bool IsReady = false;

        public BrowsCap(bool argLocalAccess)
        {
            local_access = argLocalAccess;
            IsReady = Ready();
        }

        public UserAgent GetUserAgent(string agent)
        {
            if (!IsReady) return null;
            string token = null;
            try
            {
                JToken t = j.SelectToken(agent.Replace("\"", null));

                if (t.HasValues)
                {
                    token = (string)t.SelectToken(agent, false);
                    UserAgent a = JsonConvert.DeserializeObject<UserAgent>(token);
                    Console.WriteLine(a.Parent);
                    return a;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("token error" + e.Message);
            }
            return null;
        }

        public string GetDetail(string agent, string key)
        {
            if (!IsReady) return null;
            string token = null;
            try
            {
                JToken t = j.SelectToken(agent.Replace("\"", null));
                
                if (t.HasValues)
                {
                    token = (string)t.SelectToken(agent, false);
                    UserAgent a = JsonConvert.DeserializeObject<UserAgent>(token);
                }
                //string token = (string)j.SelectToken(t.Path+ key.Replace("\"", null), false);
                Console.WriteLine("token:"+token);
                return token;
            }
            catch (Exception e){
                Console.WriteLine("token error"+e.Message);
            }
            return null;
        }

        private bool Ready()
        {
            try
            {
                string json = GetBrowsCap();
                if (json != null)
                {
                    JObject jobject = JObject.Parse(json);
                    string defaults = (string)jobject.SelectToken("DefaultProperties", false);
                    if (defaults != null) {
                        j = jobject;
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }

        private string GetBrowsCap()
        {
            string jsonpath = localappdata + "\\logextractor\\browscap.json";
            if (File.Exists(jsonpath))
            {
                try
                {
                    string json = File.ReadAllText(jsonpath);
                    return json;
                }
                catch(Exception e) {
                    MessageBag msgbag = new MessageBag();
                    msgbag.AddError(e.Message);
                    msgbag.PrintErrors();
                }
                return null;
            }
            else
            {
                if (!local_access) return null;
                
                try
                {
                    HttpClient client = new HttpClient();
                    System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;
                    client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
                    var response = client.GetAsync("https://10.19.214.112/browscap.json").Result;
                    if (response.IsSuccessStatusCode)
                    {
                        string json = response.Content.ReadAsStringAsync().Result;
                        if (json != null)
                        {
                            DirectoryInfo dir = Directory.CreateDirectory(localappdata + "\\logextractor");
                            if (dir.Exists)
                            {
                                File.AppendAllText(jsonpath, json);
                                return json;
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                    MessageBag msgbag = new MessageBag();
                    msgbag.AddError(e.Message);
                    msgbag.PrintErrors();
                }
                return null;
            }
        }

    }

}