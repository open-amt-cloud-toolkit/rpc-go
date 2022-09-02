using System;
using System.Text;
using System.Runtime.InteropServices;

namespace clientAgent
{
    class clientAgent
    {
        // use appropriately named library (.so/.dll) on desired OS
        // Linux [DllImport("rpc")]
        // Win [DllImport("rpc.dll")]
        [DllImport("rpc")]
        static extern int rpcCheckAccess();

        [DllImport("rpc")]
        static extern int rpcExec([In] byte[] rpccmd, ref IntPtr output);

        static void Main(string[] args)
        {
            int returnCode;

            Console.WriteLine("... CALLING rpcCheckAccess ...");
            returnCode = rpcCheckAccess();
            Console.WriteLine("... rpcCheckAccess completed: return code[" + returnCode + "] ");
            Console.WriteLine();

            var res = "";
            foreach (var arg in args)
            {
                res += $"{arg} ";
            }

            // Example commands to be passed in
            // string res = "activate -u wss://192.168.1.96/activate -n -profile Test_Profile";
            // string res = "amtinfo";

            IntPtr output = IntPtr.Zero;
            Console.WriteLine("... CALLING rpcExec with argument string: " + res);
            returnCode = rpcExec(Encoding.ASCII.GetBytes(res), ref output);
            Console.WriteLine("... rpcExec completed: return code[" + returnCode + "] " + Marshal.PtrToStringAnsi(output));
        }
    }
}
