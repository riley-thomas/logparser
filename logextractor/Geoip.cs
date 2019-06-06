using System;
using System.Net.Http;
using Newtonsoft.Json.Linq;

namespace logextractor
{
    class Geoip
    {
        public string city = null;
        public string state = null;
        public string country = null;
        public string country_code = null;
        protected string baseurl = "https://10.19.214.112/api/geoip/";

        public Geoip(string ip)
        {
            GetData(ip);
        }

        public void GetData(string ip)
        {
            string url = baseurl + ip;
            HttpClient client = new HttpClient();
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;
            try
            { 
                client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
                var response = client.GetAsync(url).Result;
                if (response.IsSuccessStatusCode)
                {
                    string unparsed = response.Content.ReadAsStringAsync().Result;
                    if (unparsed != null)
                    {
                        try
                        {
                            JObject json = JObject.Parse(unparsed);
                            country_code = (string)json.SelectToken("geoip.country_code", false);
                            country = (string)json.SelectToken("geoip.country", false);
                            state = (string)json.SelectToken("geoip.state", false);
                            city = (string)json.SelectToken("geoip.city", false);

                        }
                        catch (Newtonsoft.Json.JsonReaderException e) {}
                    }
                }
            }
            catch (Exception e) {}
            client.Dispose();
        }

        public bool HasData()
        {
            if(city == null && state == null && country == null) return false;
            return true;
        }

        public string DataString()
        {
            if (HasData())
            {
                string text = city;
                if (state != null) text += " " + state;
                if (country != null) text += " " + country;
                text = text.Trim();
                return text;
            }
            return null;
        }

    }


}
