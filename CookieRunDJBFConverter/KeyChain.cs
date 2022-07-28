using System.Collections.Generic;

namespace CookieRunDJBFConverter
{
    static class KeyChain
    {
        public static int Index { get; set; }
        public static int Count => Entries.Count;

        private static readonly List<Entry> Entries;
        
        static KeyChain()
        {
            Entries = new List<Entry>
            {
                // Kakao
                new Entry
                {
                     Key = new byte[]
                     {
                         0xC0, 0x01, 0xC1, 0xE1, 0x26, 0x11, 0x10, 0xDA,
                         0x90, 0x90, 0x35, 0x81, 0xFE, 0xBA, 0xA9, 0x7F,
                         0xA1, 0x45, 0x1C, 0x4F, 0x97, 0x88, 0x71, 0xFA,
                         0xC3, 0xF1, 0xF8, 0x29, 0x3D, 0xDE, 0xE2, 0xB3
                     },
                     IV = new byte[]
                     {
                         0x58, 0xA8, 0xB9, 0xDD, 0x13, 0x61, 0x62, 0xAA,
                         0x99, 0x88, 0x7A, 0x1F, 0xF2, 0x3F, 0x7C, 0x91
                     }
                },

                // QQ 2.0 (maybe others)
                new Entry
                {
                    Key = new byte[]
                    {
                        0xC0, 0x29, 0xC1, 0xE1, 0x26, 0x88, 0x71, 0xFA,
                        0xA1, 0x45, 0x1C, 0x4F, 0x97, 0xDE, 0xD2, 0xB3,
                        0x90, 0x94, 0x35, 0x81, 0xFE, 0xBA, 0xA9, 0x7F,
                        0xC3, 0xF1, 0xF8, 0x29, 0x3D, 0x11, 0x10, 0xFA,
                    },
                    IV = new byte[]
                    {
                        0x13, 0x61, 0x62, 0xAA, 0x38, 0xA8, 0xB9, 0xDD,
                        0x99, 0x6F, 0xF2, 0x3F, 0x7C, 0x91, 0x88, 0x7A
                    }
                }
            };
        }

        public static byte[] GetKey()
        {
            return Entries[Index].Key;
        }

        /// <summary>
        /// <see cref="IV"/> is salted by adding the 
        /// first byte of the checksum to all values
        /// </summary>
        public static byte[] GetIV(uint checksum)
        {
            var result = new byte[16];

            var iv = Entries[Index].IV;
            var salt = checksum & 0xFF;

            for (var i = 0; i < iv.Length; i++)
                result[i] = (byte)((iv[i] + salt) & 0xFF);

            return result;
        }

        private class Entry
        {
            public byte[] Key;
            public byte[] IV;
        }
    }

    public enum EncryptionKeys
    {
        Kakao = 1,
        QQ = 2
    }
}
