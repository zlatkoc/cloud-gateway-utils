using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;

namespace GW_encryption
{
    class Program
    {
        const string MSG = "TestčČšŠžŽ";
        const string ENCRYPTED_MSG = "16e3a986a33d740d4f928815aeffd81dc9056aeaa4571a5b30918e0d9a197b97";
        const string SHARED_SECRET = "aaaaaaaaaaaaaaaa";

        static void Main(string[] args)
        {
            var encrypted_msg = GW_helper.Encrypt(MSG, SHARED_SECRET);
            Console.WriteLine("Encrypted msg: {0}", encrypted_msg);

            var decrypted_msg = GW_helper.Decrypt(encrypted_msg, SHARED_SECRET);
            Console.WriteLine("Original msg: {0}", decrypted_msg);

            Debug.Assert(ENCRYPTED_MSG.Equals(encrypted_msg), "Encrypted msg not as expected");
            Debug.Assert(MSG.Equals(decrypted_msg), "Decrypted msg not as expected");

            Console.WriteLine("Everything ok.");
        }
    }
}
