using CommandLine;
using System;
using static CookieRunDJBFConverter.DJBFConverter;

namespace CookieRunDJBFConverter
{
    class Options
    {
        [Option('m', "mode", Required = true, HelpText = "Encrypt or Decrypt")]
        public Mode Mode { get; set; }

        [Option('k', "key", Required = true, HelpText = "Encryption key to use. Kakao or QQ")]
        public EncryptionKeys Key { get; set; } = EncryptionKeys.Kakao;

        [Option('v', "version", HelpText = "Output file version. 0, 1, 2 or 3")]
        public ushort Version { get; set; } = 1;

        [Option('f', "flags", HelpText = "Output file encryption (AES_ECB or AES_CBC) and compression (FastLZ). E.g. \"AES_ECB, FastLZ\"")]
        public Flags Flags { get; set; } = Flags.AES_ECB | Flags.FastLZ;

        [Option('s', "searchPattern", HelpText = "Filename filter")]
        public string SearchPattern { get; set; } = "*";

        public void Validate()
        {
            if (!Enum.IsDefined(typeof(EncryptionKeys), Key))
                throw new ArgumentException($"Invalid key");

            if(Mode == Mode.Encrypt)
            {
                if (Flags == 0)
                    throw new ArgumentException("No flags provided");

                if (Version < 0x100)
                    Version += 0x100;

                if (Version < 0x0100 || Version > 0x0103)
                    throw new ArgumentException("Invalid version number");

                if (Version >= 0x0102 && Flags.HasFlag(Flags.AES_ECB | Flags.AES_CBC))
                    throw new ArgumentException("Invalid flags. Only one AES mode can be set");                
            }
        }
    }

    public enum Mode : byte
    {
        Decrypt = 0,
        Encrypt = 1
    }
}
