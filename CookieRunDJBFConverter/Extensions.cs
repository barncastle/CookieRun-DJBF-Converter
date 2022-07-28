using System.IO;
using System.Runtime.InteropServices;

namespace CookieRunDJBFConverter
{
    static class Extensions
    {
        public static T Read<T>(this Stream reader) where T : struct
        {
            var size = Marshal.SizeOf<T>();

            var buffer = new byte[size];
            reader.Read(buffer, 0, buffer.Length);

            var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            var result = Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());

            handle.Free();
            return result;
        }

        public static void Write<T>(this Stream reader, T value) where T : struct
        {
            var size = Marshal.SizeOf<T>();
            var buffer = new byte[size];

            var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            Marshal.StructureToPtr(value, handle.AddrOfPinnedObject(), true);
            handle.Free();

            reader.Write(buffer, 0, buffer.Length);
        }
    }
}
