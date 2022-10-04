using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CookieRunDJBFConverter
{
    public unsafe class DJBFConverter
    {
        public static byte[] Decrypt(string path)
        {
            using (var fs = File.OpenRead(path))
            {
                var header = fs.Read<Header>();

                // swap endian
                header.Version = (ushort)((header.Version >> 8) | ((header.Version & 0xFF) << 8));

                // flag fixes for various versions
                if (header.Version < 0x0101)
                    header.Flags &= ~Flags.FastLZ;
                if (header.Version < 0x0102)
                    header.Flags &= ~Flags.AES_CBC;

                // ver 0x0100 files have bad data if 128 bit aligned
                if (header.DataSuffixSize > 0xF)
                    header.DataSuffixSize = 0;

                Console.WriteLine($"\tDetected: [Version: {header.Version:X4} Flags: {header.Flags.Prettify()}]");

                // copy out the remaining data and append the suffix bytes
                var dataSize = (int)(fs.Length - fs.Position);
                var buffer = new byte[dataSize + header.DataSuffixSize];

                fs.Read(buffer, 0, dataSize);
                Array.Copy(header.DataSuffix, 0, buffer, dataSize, header.DataSuffixSize);

                // AES decrypt
                if ((header.Flags & (Flags.AES_CBC | Flags.AES_ECB)) != 0)
                    buffer = AESDecrypt(header, buffer);

                // FastLZ decompress
                if (header.Flags.HasFlag(Flags.FastLZ))
                    buffer = FastLZDecompress(header, buffer);

                var checksum = CRCUnsafe.Crc32(buffer);
                if (checksum != header.Checksum)
                    throw new Exception($"Checksum :: {checksum:X8} != {header.Checksum:X8}");

                return buffer;
            }
        }

        public static byte[] Encrypt(string path, ushort version, Flags flags)
        {
            var buffer = File.ReadAllBytes(path);

            var header = new Header
            {
                Magic = 0x46424A44, // "DJBF"
                Version = (ushort)((version >> 8) | ((version & 0xFF) << 8)),
                Checksum = CRCUnsafe.Crc32(buffer),
                DataSizeLo = buffer.Length,
                DataSuffix = new byte[0xF],
                Flags = flags
            };

            // flag fixes for various versions
            if (version < 0x0101)
                flags &= ~Flags.FastLZ;
            if (version < 0x0102)
                flags &= ~Flags.AES_CBC;

            // FastLZ compress
            if (flags.HasFlag(Flags.FastLZ))
                buffer = FastLZCompress(header, buffer);

            // align to 128 bits and calculate suffix size
            if (buffer.Length % 16 != 0)
            {
                header.DataSuffixSize = (byte)(16 - (buffer.Length % 16));
                Array.Resize(ref buffer, buffer.Length + header.DataSuffixSize);
            }

            // AES encrypt
            if ((flags & (Flags.AES_CBC | Flags.AES_ECB)) != 0)
                buffer = AESEncrypt(header, buffer);

            // copy the suffix to the header
            Array.Copy(
                buffer,
                buffer.Length - header.DataSuffixSize,
                header.DataSuffix,
                0,
                header.DataSuffixSize);

            using (var ms = new MemoryStream(buffer.Length + 37))
            {
                ms.Write(header);
                ms.Write(buffer, 0, buffer.Length - header.DataSuffixSize);
                return ms.ToArray();
            }
        }

        private static byte[] AESEncrypt(Header header, byte[] data)
        {
            // create AES instance with salted IV
            var aes = new RijndaelManaged()
            {
                Key = KeyChain.GetKey(),
                IV = KeyChain.GetIV(header.Checksum),
                Padding = PaddingMode.None
            };

            // set mode and created encryptor
            ICryptoTransform encryptor;
            if (header.Flags.HasFlag(Flags.AES_CBC))
            {
                aes.Mode = CipherMode.CBC;
                encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            }
            else
            {
                aes.Mode = CipherMode.ECB;
                encryptor = aes.CreateEncryptor(aes.Key, null);
            }

            // encrypt
            using (var msIn = new MemoryStream(data))
            using (var msOut = new MemoryStream(data.Length))
            using (var cs = new CryptoStream(msOut, encryptor, CryptoStreamMode.Write))
            {
                msIn.WriteTo(cs);

                // truncate padding
                if (msOut.Length > header.DataSizeLo)
                    msOut.SetLength(header.DataSizeLo);

                return msOut.ToArray();
            }
        }

        private static byte[] AESDecrypt(Header header, byte[] data)
        {
            // create AES instance with salted IV
            var aes = new RijndaelManaged()
            {
                Key = KeyChain.GetKey(),
                IV = KeyChain.GetIV(header.Checksum),
                Padding = PaddingMode.None
            };

            // set mode and created decryptor
            ICryptoTransform decryptor;
            if (header.Flags.HasFlag(Flags.AES_CBC))
            {
                aes.Mode = CipherMode.CBC;
                decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            }
            else
            {
                aes.Mode = CipherMode.ECB;
                decryptor = aes.CreateDecryptor(aes.Key, null);
            }

            // decrypt
            using (var msIn = new MemoryStream(data))
            using (var msOut = new MemoryStream(data.Length))
            using (var cs = new CryptoStream(msIn, decryptor, CryptoStreamMode.Read))
            {
                cs.CopyTo(msOut);

                // truncate padding
                if (msOut.Length > header.DataSizeLo)
                    msOut.SetLength(header.DataSizeLo);

                return msOut.ToArray();
            }
        }

        private static byte[] FastLZCompress(Header header, byte[] data)
        {
            var buffer = new byte[header.DataSizeLo + 12 - 1]; // max expansion

            fixed (byte* input = &data[0])
            fixed (byte* output = &buffer[0])
            {
                var written = FastLZ.Compress(input, data.Length, output);

                // trucate to real size
                if (written != buffer.Length)
                    Array.Resize(ref buffer, written);

                return buffer;
            }
        }

        private static byte[] FastLZDecompress(Header header, byte[] data)
        {
            var buffer = new byte[header.DataSizeLo];

            fixed (byte* input = &data[0])
            fixed (byte* output = &buffer[0])
            {
                var read = FastLZ.Decompress(input, data.Length, output, buffer.Length);

                if (read != header.DataSizeLo)
                    throw new Exception($"Fast_LZ : {read} != {header.DataSizeLo}");

                return buffer;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct Header
        {
            public uint Magic;
            public ushort Version; // BE
            public ushort Reserved;
            public uint Checksum;
            public int DataSizeLo;
            public int DataSizeHi;
            public Flags Flags;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)]
            public byte[] DataSuffix;
            public byte DataSuffixSize;
        }

        [Flags]
        public enum Flags : byte
        {
            AES_ECB = 0x1,
            AES_CBC = 0x2, // ≥ 0x0102
            FastLZ = 0x80, // ≥ 0x0101
        }
    }
}
