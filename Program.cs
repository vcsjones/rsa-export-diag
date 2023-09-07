using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

#pragma warning disable CA1416

unsafe {
    // Do this first so we get the bare modules needed loaded.
    Console.WriteLine($"{SafeEvpPKeyHandle.OpenSslVersion:X8}");

    ProcessModule libShim = null;
    ProcessModule libCrypto = null;

    using Process currentProcess = Process.GetCurrentProcess();

    foreach (ProcessModule module in currentProcess.Modules) {
        string fileName = Path.GetFileName(module.FileName);

        if (fileName.Equals("libSystem.Security.Cryptography.Native.OpenSsl.so", StringComparison.Ordinal)) {
            libShim = module;
        }
        else if (fileName.StartsWith("libcrypto.so", StringComparison.Ordinal)) {
            libCrypto = module;
        }
    }

    if (libShim is null) {
        throw new Exception("Crypto shim is not loaded.");
    }
    else {
        Console.WriteLine($"Shim path: {libShim.FileName}");
    }

    if (libCrypto is null) {
        throw new Exception("libcrypto is not loaded.");
    }
    else {
        Console.WriteLine($"libcrypto path: {libCrypto.FileName}");
    }

    IntPtr pLibCrypto = NativeLibrary.Load(libCrypto.FileName);
    IntPtr pLibShim = NativeLibrary.Load(libShim.FileName);

    // First, make sure we can reproduce the original problem.
    IntPtr pGetPkcs8PrivateKeySize = NativeLibrary.GetExport(pLibShim, "CryptoNative_GetPkcs8PrivateKeySize");
    IntPtr pEvpPkey2Pkcs8 = NativeLibrary.GetExport(pLibCrypto, "EVP_PKEY2PKCS8");
    IntPtr pErrPrintErrorCb = NativeLibrary.GetExport(pLibCrypto, "ERR_print_errors_cb");

    var funcGetPkcs8PrivateKeySize = (delegate* unmanaged[Cdecl]<IntPtr, out int, int>)pGetPkcs8PrivateKeySize;
    var funcEvpPkey2Pkcs8 = (delegate* unmanaged[Cdecl]<IntPtr, IntPtr>)pEvpPkey2Pkcs8;
    var funcErrPrintErrorCb = (delegate* unmanaged[Cdecl]<delegate* unmanaged[Cdecl]<byte*, IntPtr, void*, int>, void*, void>)pErrPrintErrorCb;

    Console.WriteLine("\nAttempting to reproduce original error.");
    Console.WriteLine(new string('-', 32));

    using (RSAOpenSsl rsaOpenSsl = new RSAOpenSsl(2048))
    {
        using SafeEvpPKeyHandle keyHandle = rsaOpenSsl.DuplicateKeyHandle();
        IntPtr pKeyHandle = keyHandle.DangerousGetHandle();

        int result = funcGetPkcs8PrivateKeySize(pKeyHandle, out int p8Size);
        const int Success = 1;
        const int Error = -1;
        const int MissingPrivateKey = -2;

        switch (result) {
            case Success:
                Console.WriteLine("CryptoNative_GetPkcs8PrivateKeySize was successful.");
                Console.WriteLine($"The PKCS8 size is {p8Size}.");
                break;
            case Error:
                Console.WriteLine("CryptoNative_GetPkcs8PrivateKeySize errored.");
                break;
            case MissingPrivateKey:
                Console.WriteLine("CryptoNative_GetPkcs8PrivateKeySize reported no private key.");
                break;
        }
    }

    Console.WriteLine("\nAttempting native OpenSSL invocations.");
    Console.WriteLine(new string('-', 32));

    using (RSAOpenSsl rsaOpenSsl = new RSAOpenSsl(2048))
    {
        // RSA dummy = RSA.Create(2048);
        // rsaOpenSsl.ImportParameters(dummy.ExportParameters(false));
        using SafeEvpPKeyHandle keyHandle = rsaOpenSsl.DuplicateKeyHandle();
        IntPtr pKeyHandle = keyHandle.DangerousGetHandle();

        IntPtr result = funcEvpPkey2Pkcs8(pKeyHandle);

        if (result == IntPtr.Zero) {
            Console.WriteLine("Export failed. Dumping OpenSSL error queue.");
            funcErrPrintErrorCb(&Callback, null);
        }
        else {
            Console.WriteLine($"Export succeeded. Handle is {result:X16}");
        }
    }
}

[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
static unsafe int Callback(byte* str, IntPtr len, void* u) {
    string val = System.Text.Encoding.UTF8.GetString(str, len.ToInt32());
    Console.Write(val);
    return 1;
}