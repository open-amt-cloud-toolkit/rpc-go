using System;
using System.Text;
using System.Runtime.InteropServices;

namespace clientAgent
{
    class clientAgent
    {
        // use appropriately named (.so/.dll) on desired OS
        [DllImport("rpclib.so", EntryPoint = "checkAccess")]
        static extern void checkAccess();

        // use appropriately named library (.so/.dll) on desired OS
        [DllImport("rpclib.so", EntryPoint = "rpcExec")]
        static extern string rpc([In] byte[] rpccmd, ref IntPtr output);

        static void Main(string[] args)
        {
            var res = "";
            foreach (var arg in args)
            {
                res += $"{arg} ";
            }

            // Example commands to be passed in
            // string res = "activate -u wss://192.168.1.96/activate -n -profile Test_Profile";
            // string res = "amtinfo";

            IntPtr output = IntPtr.Zero;
            rpc(Encoding.ASCII.GetBytes(res), ref output);
            Console.WriteLine("Output from RunRPC: " + Marshal.PtrToStringAnsi(output));
        }
    }
}
