using System;

namespace cs_x86
{
    /// <summary>
    /// Wrapper for disassembling x86 bytecode
    /// </summary>
    public class Capstone : IDisposable
    {
        private CapstoneWrapper Wrapper;

        /// <summary>
        /// Create a new instance of Capstone, setup for x86 disassembly
        /// </summary>
        /// <returns>Instance of disposable Capstone class</returns>
        public static Capstone CreateEngine()
        {
            Capstone Instance = new Capstone();

            Instance.Wrapper = new CapstoneWrapper();
            Instance.Wrapper.Open(cs_arch.CS_ARCH_X86, cs_mode.CS_MODE_32);
            Instance.Wrapper.SetOption(cs_opt_type.CS_OPT_SYNTAX, cs_opt_value.CS_OPT_SYNTAX_INTEL);

            return Instance;
        }

        /// <summary>
        /// Cleanup the Capstone library
        /// </summary>
        public void Dispose()
        {
            Wrapper.Close();
        }

        /// <summary>
        /// Fetch the Capstone library version number as a string
        /// </summary>
        /// <returns>Formatted Capstone library version</returns>
        public static string Version()
        {
            int Major = 0;
            int Minor = 0;
            CapstoneWrapper.Version(out Major, out Minor);

            return string.Format("capstone-{0}.0.{1}", Major, Minor);
        }

        /// <summary>
        /// Disassemble a byte array, triggering Callback on each instruction
        /// </summary>
        /// <param name="Data">Assembly instructions</param>
        /// <param name="Address">Address of the first instruction</param>
        /// /// <param name="Callback">Delegate function called per-instruction</param>
        public void DisassembleIt(byte[] Data, ulong Address, OnDisassembly Callback)
        {
            Wrapper.StartDisassembly();
            Wrapper.DisassembleIt(Data, Address, Callback);
            Wrapper.EndDisassembly();
        }

        /// <summary>
        /// Disassemble a byte array, triggering Callback on each instruction
        /// </summary>
        /// <param name="Data">Assembly instructions</param>
        /// <param name="Address">Address of the first instruction</param>
        /// /// <param name="Callback">Delegate function called per-instruction</param>
        public static void DisassembleAll(byte[] Data, ulong Address, OnDisassembly Callback)
        {
            using (Capstone Engine = CreateEngine())
            {
                Engine.DisassembleIt(Data, Address, Callback);
            }
        }
    }
}
