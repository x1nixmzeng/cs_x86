using System;
using cs_x86;

namespace Tests.cs_x86
{
    class Program
    {
        static void OnDisassembleInstruction(CapstoneInstruction Instruction)
        {
            string ByteString = "";
            foreach (byte B in Instruction.Bytecode)
            {
                ByteString += string.Format("{0:x2} ", B);
            }

            Console.WriteLine("{0:X8} {1,-20} {2}", Instruction.Address, ByteString, Instruction.Disassembly);
        }

        static void Main(string[] args)
        {
            Console.WriteLine(Capstone.Version());

            //00FBD440 55                   push        ebp  
            //00FBD441 8B EC                mov         ebp,esp  
            //00FBD443 6A FF                push        0FFFFFFFFh  
            //00FBD445 68 9B 2C FC 00       push        0FC2C9Bh  
            //00FBD44A 64 A1 00 00 00 00    mov         eax,dword ptr fs:[00000000h]  
            //00FBD450 50                   push        eax  
            //00FBD451 81 EC B0 02 00 00    sub         esp,2B0h  
            //00FBD457 53                   push        ebx  
            //00FBD458 56                   push        esi  
            //00FBD459 57                   push        edi  
            //00FBD45A 8D BD 44 FD FF FF    lea         edi,[ebp-2BCh]  
            //00FBD460 B9 AC 00 00 00       mov         ecx,0ACh  
            //00FBD465 B8 CC CC CC CC       mov         eax,0CCCCCCCCh  
            //00FBD46A F3 AB                rep stos    dword ptr es:[edi]  

            byte[] data = new byte[]
            {
                0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x9B, 0x2C, 0xFC, 0x00, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00,
                0x50, 0x81, 0xEC, 0xB0, 0x02, 0x00, 0x00, 0x53, 0x56, 0x57, 0x8D, 0xBD, 0x44, 0xFD, 0xFF, 0xFF,
                0xB9, 0xAC, 0x00, 0x00, 0x00, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xF3, 0xAB
            };

            try
            {
                Capstone.DisassembleAll(data, 0x00FBD440, OnDisassembleInstruction);
            }
            catch (CapstoneError error)
            {
                Console.WriteLine(string.Format("Error: {0}", error.Message));
            }
        }
    }
}
