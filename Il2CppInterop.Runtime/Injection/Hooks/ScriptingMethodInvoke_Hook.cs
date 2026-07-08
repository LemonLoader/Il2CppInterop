using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Il2CppInterop.Common;
using Microsoft.Extensions.Logging;

namespace Il2CppInterop.Runtime.Injection.Hooks
{
    /// <summary>
    /// Hook for scripting_method_invoke to prevent crashes when 
    /// </summary>
    internal unsafe class ScriptingMethodInvoke_Hook : Hook<ScriptingMethodInvoke_Hook.MethodDelegate>
    {
        public override string TargetMethodName => "ScriptingMethodInvoke";
        public override MethodDelegate GetDetour() => Hook;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void* MethodDelegate(void* method, void* obj, void* args, void* exc, [MarshalAs(UnmanagedType.U1)] bool something);

        [DllImport("liblog.so")]
        private static extern int __android_log_write(int prio, [MarshalAs(UnmanagedType.LPUTF8Str)] string tag, [MarshalAs(UnmanagedType.LPUTF8Str)] string text);

        private void* Hook(void* method, void* obj, void* args, void* exc, [MarshalAs(UnmanagedType.U1)] bool something)
        {
            if (method == null)
                return (void*)0x0;

            return Original(method, obj, args, exc, something);
        }

        public override IntPtr FindTargetMethod()
        {
            var handle = NativeLibrary.Load("libunity.so");

            // known-good exported symbol to calculate base address of libunity.so
            NativeLibrary.TryGetExport(handle, "JNI_OnLoad", out var jniOnLoadRuntimeAddr);

            var loadBias = ElfSymbolHelpers.FindLoadBias("libunity.so", out var path);
            var jniOnLoadFileAddr = ElfSymbolHelpers.ResolveFileRelativeSymbol(path, "JNI_OnLoad");

            ulong trueBias = (ulong)jniOnLoadRuntimeAddr.ToInt64() - (ulong)jniOnLoadFileAddr.ToInt64();

            var targetFileAddr = ElfSymbolHelpers.ResolveFileRelativeSymbol(
                path,
                "_Z23scripting_method_invoke18ScriptingMethodPtr18ScriptingObjectPtrR18ScriptingArgumentsP21ScriptingExceptionPtrb"
            );

            var ptr = new IntPtr((long)(trueBias + (ulong)targetFileAddr.ToInt64()));

            Logger.Instance.LogTrace("ScriptingMethodInvoke: 0x{Addr}", ptr.ToInt64().ToString("X2"));
            return ptr;
        }
    }
}
