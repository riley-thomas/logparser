using UAParser;

namespace logextractor
{
    class UserAgent
    {
        public string agent;
        public ClientInfo client = null;

        public UserAgent(Conf conf, string argAgent = null)
        {
            agent = argAgent;
            if (agent != null)
            {
                client = conf.UAParser.Parse(agent);
            }
        }

    }

}
