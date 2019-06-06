using System;
using System.Collections.Generic;

namespace logextractor
{
    class MessageBag
    {

        public List<string> errors = new List<string>();
        public List<string> messages = new List<string>();

        public MessageBag()
        {
            //
        }

        public MessageBag(string argType, string argString)
        {
            if (argType == "message")
            {
                AddMessage(argString);
            }
            else
            {
                AddError(argString);
            }
        }

        public void AddMessage(string message)
        {
            if (!messages.Contains(message)) messages.Add(message);
        }

        public void AddError(string error)
        {
            if (!errors.Contains(error)) errors.Add(error);
        }

        public void PrintErrors()
        {
            if(errors.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                foreach(string error in errors)
                {
                    Console.WriteLine(error);
                }
                Console.ResetColor();
            }
        }

        public void PrintMessages()
        {
            if (messages.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                foreach (string message in messages)
                {
                    Console.WriteLine(message);
                }
                Console.ResetColor();
            }
        }
                    
    }
}
