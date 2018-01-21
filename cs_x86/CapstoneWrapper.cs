using System;
using System.Runtime.InteropServices;

namespace cs_x86
{
    public struct CapstoneInstruction
    {
        public ulong Address;
        public byte[] Bytecode;
        public string Disassembly;
    }

    public delegate void OnDisassembly(CapstoneInstruction Instruction);

    internal class CapstoneWrapper
    {
        IntPtr Handle;
        cs_err LastError;

        IntPtr InstrBuffer;

        cs_insn LastInstruction;

        public CapstoneWrapper()
        {
            Handle = IntPtr.Zero;
            LastError = cs_err.CS_ERR_OK;

            LastInstruction = new cs_insn();
        }

        public static uint Version()
        {
            int Major = 0;
            int Minor = 0;

            return CapstoneAPI.cs_version(out Major, out Minor);
        }

        public static void Version(out int Major, out int Minor)
        {
            CapstoneAPI.cs_version(out Major, out Minor);
        }

        public bool HasError
        {
            get
            {
                return LastError != cs_err.CS_ERR_OK;
            }
        }

        public void SetOption(cs_opt_type Type, cs_opt_value Value)
        {
            LastError = CapstoneAPI.cs_option(Handle, Type, (uint)Value);
        }

        public void Open(cs_arch Architecture, cs_mode Mode)
        {
            LastError = CapstoneAPI.cs_open(Architecture, Mode, out Handle);
        }
        
        public void Close()
        {
            LastError = CapstoneAPI.cs_close(ref Handle);
        }

        public void StartDisassembly()
        {
            InstrBuffer = CapstoneAPI.cs_malloc(Handle);
        }

        public void EndDisassembly()
        {
            CapstoneAPI.cs_free(InstrBuffer, 1);
            InstrBuffer = IntPtr.Zero;
        }

        public void DisassembleIt(byte[] Data, ulong Address, OnDisassembly Callback)
        {
            IntPtr DataPtr = Marshal.UnsafeAddrOfPinnedArrayElement(Data, 0);
            uint CodeSize = (uint)Data.Length;
            ulong CurrentAddress = Address;

            CapstoneInstruction Instruction = new CapstoneInstruction();

            ulong LastAddress = CurrentAddress;
            while (CodeSize > 0)
            {
                if (!CapstoneAPI.cs_disasm_iter(Handle, ref DataPtr, ref CodeSize, ref CurrentAddress, InstrBuffer))
                    break;

                // Fix bug where cs_disasm_iter can get stuck in a loop but return true
                if (CurrentAddress == LastAddress)
                    break;
                
                LastInstruction.Read(InstrBuffer);

                Instruction.Address = LastInstruction.address;
                Instruction.Disassembly = string.Format("{0,-12}{1}", LastInstruction.mnemonic, LastInstruction.op_str);
                Instruction.Bytecode = new byte[LastInstruction.size];
                Array.Copy(LastInstruction.bytes, Instruction.Bytecode, LastInstruction.size);

                Callback(Instruction);

                LastAddress = CurrentAddress;
            }
        }
    }
}
