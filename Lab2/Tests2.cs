using System;

namespace CryptoLab2;

public static class Tests2
{
    public static void Run()
    {
        Check("Ферма", new FermatTest());
        Check("Соловей — Штрассен", new SolovayStrassenTest());
        Check("Миллер — Рабин", new MillerRabinTest());
    }

    private static void Check(string name, IPrimeTest test)
    {
        Console.WriteLine($"\n< {name} >");

        int[] numbers = {-5, 0, 1, 2, 3, 4, 9, 17, 41, 97, 100};

        bool[] expected = {false, false, false, true, true, false,false, true, true, true, false};

        double probability = 0.99;

        for (int i = 0; i < numbers.Length; i++)
        {
            int n = numbers[i];

            bool actual = test.IsPrime(n, probability);

            Console.WriteLine($"{n}: {actual}; ожидается {expected[i]}");
        }
    }
}