using CommandLine;
using System;
using System.IO;
using System.Threading.Tasks;

namespace CookieRunDJBFConverter
{
    class Program
    {
        static void Main(string[] args)
        {
            var parser = new Parser(s =>
            {
                s.HelpWriter = Console.Error;
                s.CaseInsensitiveEnumValues = true;
                s.AutoVersion = false;
            });

            parser
                .ParseArguments<Options>(args)
                .MapResult(Run, Task.FromResult)
                .Wait();
        }

        static async Task Run(Options options)
        {
            options.Validate();

            KeyChain.Index = (int)options.Key;

            foreach (var file in Directory.GetFiles(".", options.SearchPattern))
            {
                byte[] buffer;
                string ext;

                if (options.Mode == Mode.Decrypt)
                {
                    ext = ".bin";
                    Console.WriteLine($"Decrypting {Path.GetFileName(file)}");
                    buffer = DJBFConverter.Decrypt(file);
                }
                else
                {
                    ext = ".djb";
                    Console.WriteLine($"Encrypting {Path.GetFileName(file)}");
                    buffer = DJBFConverter.Encrypt(file, options.Version, options.Flags);
                }

                File.WriteAllBytes(Path.ChangeExtension(file, ext), buffer);
            }

            await Task.CompletedTask;
        }
    }
}
