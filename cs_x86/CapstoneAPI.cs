using System;
using System.Runtime.InteropServices;

namespace cs_x86
{
    internal static class CapstoneAPI
    {
        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint cs_version([Out] out int major, [Out] out int minor);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern bool cs_support([In] int query);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern cs_err cs_open([In] cs_arch arch, [In] cs_mode mode, [Out] out IntPtr handle);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern cs_err cs_close([In, Out] ref IntPtr handle);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern cs_err cs_option([In] IntPtr handle, [In] cs_opt_type type, [In] uint value);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern cs_err cs_errno([In] IntPtr handle);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern string cs_strerror([In] cs_err code);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint cs_disasm([In] IntPtr handle, [In] byte[] code, [In] uint code_size, [In] ulong address, [In] uint count, [Out] out IntPtr insn);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void cs_free([In] IntPtr insn, [In] uint count);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr cs_malloc([In] IntPtr handle);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern bool cs_disasm_iter([In] IntPtr handle, [In, Out] ref IntPtr code, [In, Out] ref uint codeSize, [In, Out] ref ulong address, [In] IntPtr insn);
        
        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern string cs_reg_name([In] IntPtr handle, [In] uint reg_id);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern string cs_insn_name([In] IntPtr handle, [In] uint insn_id);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern string cs_group_name([In] IntPtr handle, [In] uint group_id);
    }
}
