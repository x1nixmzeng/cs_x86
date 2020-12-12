using System;
using System.Runtime.InteropServices;
using System.Text;

namespace cs_x86
{
    internal class cs_insn
    {
        public uint id;
        public ulong address;
        public ushort size;
        public byte[] bytes;
        public string mnemonic;
        public string op_str;

        static byte[] buffer = new byte[256];

        private void GetStr(out string str, int MaxSize)
        {
            int Result = Array.FindIndex(buffer, b => b == '\0');
            if( Result == -1 )
                Result = MaxSize;

            str = Encoding.ASCII.GetString(buffer, 0, Result);
        }

        public void Read(IntPtr Data)
        {
            id = (uint)Marshal.ReadInt32(Data);
            address = (ulong)Marshal.ReadInt64(Data, 8);
            size = (ushort)Marshal.ReadInt16(Data, 16);

            bytes = new byte[24];
            Marshal.Copy(Data + 18, bytes, 0, 24);

            Marshal.Copy(Data + 42, buffer, 0, 32);
            GetStr(out mnemonic, 32);
            
            Marshal.Copy(Data + 74, buffer, 0, 160);
            GetStr(out op_str, 160);
        }
    }
}
