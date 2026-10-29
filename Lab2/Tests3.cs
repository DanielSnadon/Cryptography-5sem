using System;
using System.Numerics;

namespace CryptoLab2;

public static class Tests3
{
    public static void Run()
    {
        var rsa = new Rsa(Rsa.TestType.MillerRabin, 0.99, 32);

        for (int generation = 1; generation <= 2; generation++)
        {
            rsa.GenerateKeys();

            var key = rsa.GetPublicKey();

            Console.WriteLine($"\n< RSA: генерация {generation} >");
            Console.WriteLine($"n = {key.n}");
            Console.WriteLine($"e = {key.e}");

            BigInteger[] numbers = {0, 1, 67, key.n - 1};

            foreach (BigInteger original in numbers)
            {
                BigInteger encrypted = rsa.Encrypt(original);
                BigInteger decrypted = rsa.Decrypt(encrypted);

                Console.WriteLine($"Исходное: {original}, " + $"шифротекст: {encrypted}, " + $"восстановленное: {decrypted}");
            }
        }
    }
}