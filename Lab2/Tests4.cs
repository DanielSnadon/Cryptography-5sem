using System;

namespace CryptoLab2;

public static class Tests4
{
    public static void Run()
    {
        var rsa = new Rsa(Rsa.TestType.MillerRabin, 0.9999, 32);

        for (int testNumber = 1; testNumber <= 3; testNumber++)
        {
            Console.WriteLine($"\n< Атака Винера: тест {testNumber} >");

            var keys = rsa.GenerateWeakKeys();

            Console.WriteLine($"Открытый ключ: n = {keys.n}, e = {keys.e}");
            Console.WriteLine($"Настоящее d = {keys.d}");
            Console.WriteLine($"Настоящее phi = {keys.phi}");

            var attack = WienerAttack.Attack(keys.n, keys.e);

            Console.WriteLine("\nПодходящие дроби:");

            foreach (var fraction in attack.fractions)
            {
                Console.WriteLine(
                    $"{fraction.numerator}/{fraction.denominator}");
            }

            Console.WriteLine($"\nНайдено: {attack.found}");

            if (!attack.found)
            {
                Console.WriteLine("Нееееет... Секретная экспонента не найдена.");
                continue;
            }

            Console.WriteLine($"Найденное d = {attack.d}");
            Console.WriteLine($"Найденное phi = {attack.phi}");
        }
    }
}