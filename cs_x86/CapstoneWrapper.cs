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

    public class CapstoneError : Exception
    {
        public CapstoneError(string Message) : base(Message)
        { }
    }

    internal class CapstoneWrapper
    {
        private IntPtr Handle;
        private cs_err LastError;

        private IntPtr InstrBuffer;

        private cs_insn LastInstruction;

        public CapstoneWrapper()
        {
            Handle = IntPtr.Zero;
            LastError = cs_err.CS_ERR_OK;

            LastInstruction = new cs_insn();
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

        public string ErrorString
        {
            get
            {
                IntPtr ErrorPtr = CapstoneAPI.cs_strerror(LastError);
                if (ErrorPtr != IntPtr.Zero)
                {
                    return Marshal.PtrToStringAnsi(ErrorPtr);
                }

                return "";
            }
        }

        private void ThrowOnError(cs_err Result)
        {
            LastError = Result;
            if (HasError)
            {
                throw new CapstoneError(ErrorString);
            }
        }

        public void SetOption(cs_opt_type Type, cs_opt_value Value)
        {
            ThrowOnError(CapstoneAPI.cs_option(Handle, Type, (uint)Value));
        }

        public void Open(cs_arch Architecture, cs_mode Mode)
        {
            ThrowOnError(CapstoneAPI.cs_open(Architecture, Mode, out Handle));
        }

        public void Close()
        {
            ThrowOnError(CapstoneAPI.cs_close(ref Handle));
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
