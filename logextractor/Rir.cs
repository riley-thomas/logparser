using System;
using System.Net.Http;
using Newtonsoft.Json.Linq;

namespace logextractor
{
    class Rir
    {
        public string orgname = null;
        public string registry = "ARIN";
        public string ip = null;
        public bool local = false;

        public Rir(string argIp, bool argLocal = false)
        {
            ip = argIp;
            local = argLocal; 
            orgname = GetOrgName();            
        }

        protected string GetUrl(string registry)
        {
            if (local)
            {
               return "https://10.19.214.112/api/" + registry + "/" + ip;
            }
            else
            {
                return registry == "ripe" ? ("https://rest.db.ripe.net/search/?type-filter=inetnum&source=ripe&include-tags=org&resource-holder=true&limit=1&query-string=" + ip) : ("http://whois.arin.net/rest/ip/" + ip);
            }
        }

        public string GetOrgName()
        {
            string name = null;
            HttpClient client = new HttpClient();
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;
            client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
            try
            {
                name = GetArin(client);
                if(name == "RIPE Network Coordination Centre") name = GetRipe(client);
            }
            catch (Exception e) {}
            client.Dispose();
            return name;
        }

        protected string GetArin(HttpClient client)
        {
            string name = null;
            try
            {
                var response = client.GetAsync(GetUrl("arin")).Result;
                if (response.IsSuccessStatusCode)
                {
                    try
                    {
                        string unparsed = response.Content.ReadAsStringAsync().Result;
                        if (unparsed != null)
                        {
                            try
                            {
                                JObject json = JObject.Parse(unparsed);
                                name = (string)json.SelectToken("net.orgRef.@name", false);
                                if (name == null)
                                {
                                    name = (string)json.SelectToken("net.customerRef.@name", false);
                                }
                            }
                            catch (Newtonsoft.Json.JsonReaderException e) { }
                        }
                    }
                    catch (Newtonsoft.Json.JsonReaderException e) { }
                }
                return name;
            }
            catch (Exception e)
            {
                return name;
            }
        }

        protected string GetRipe(HttpClient client)
        {
            string name = null;
            try
            {
                var response = client.GetAsync(GetUrl("ripe")).Result;
                if (response.IsSuccessStatusCode)
                {
                    try
                    {
                        string unparsed = response.Content.ReadAsStringAsync().Result;
                        if (unparsed != null)
                        {
                            try
                            {
                                JObject json = JObject.Parse(unparsed);
                                name = (string)json.SelectToken("objects.object[0].resource-holder.name", false);
                                registry = "RIPE";
                            }
                            catch (Newtonsoft.Json.JsonReaderException e) {}
                        }
                    }
                    catch (Newtonsoft.Json.JsonReaderException e) { }
                }
                return name;
            }
            catch(Exception e)
            {
                return name;
            }
        }
    }
}
