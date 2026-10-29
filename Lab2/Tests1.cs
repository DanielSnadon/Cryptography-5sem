using System;

namespace CryptoLab2;

public static class Tests1
{
    public static void Run()
    {
        Console.WriteLine("\n< Алгоритмы Евклида >");

        Console.WriteLine($"НОД(48, 18): {NumberTheory.Gcd(48, 18)}; ожидается 6");

        Console.WriteLine($"Бинарный НОД(48, 18): {NumberTheory.BinaryGcd(48, 18)}; ожидается 6");

        var outs = NumberTheory.ExtGcd(48, 18);
        Console.WriteLine($"Расширенный Евклид: НОД = {outs.gcd}, x = {outs.x}, y = {outs.y}");

        Console.WriteLine($"Проверка Безу: 48*x + 18*y = {48 * outs.x + 18 * outs.y}; ожидается 6");

        Console.WriteLine("\n< Степень по модулю >");

        Console.WriteLine($"3^13 mod 17: {NumberTheory.ModPow(3, 13, 17)}; ожидается 12");

        Console.WriteLine("\n< Символ Лежандра >");

        Console.WriteLine($"(2/7): {NumberTheory.LegendreSymbol(2, 7)}; ожидается 1");

        Console.WriteLine($"(3/7): {NumberTheory.LegendreSymbol(3, 7)}; ожидается -1");

        Console.WriteLine($"(14/7): {NumberTheory.LegendreSymbol(14, 7)}; ожидается 0");

        Console.WriteLine("\n< Символ Якоби >");

        Console.WriteLine($"(2/15): {NumberTheory.JacobiSymbol(2, 15)}; ожидается 1");

        Console.WriteLine($"(7/15): {NumberTheory.JacobiSymbol(7, 15)}; ожидается -1");

        Console.WriteLine($"(3/15): {NumberTheory.JacobiSymbol(3, 15)}; ожидается 0");

        Console.WriteLine("\n< Функция Эйлера >");

        int[] numbers = { 1, 8, 9, 12, 13, 36 };
        int[] expectedPhi = { 1, 4, 6, 4, 12, 12 };

        for (int i = 0; i < numbers.Length; i++)
        {
            int n = numbers[i];

            Console.WriteLine(
                $"n = {n}: " +
                $"базовое = {NumberTheory.EulerBasic(n)}, " +
                $"разложение = {NumberTheory.EulerFactorization(n)}, " +
                $"Фурье = {NumberTheory.EulerFourier(n)}; " +
                $"ожидается {expectedPhi[i]}");
        }

        Console.WriteLine("\n< Функция Кармайкла >");

        int[] carmichaelNumbers = { 1, 8, 9, 15, 72 };
        int[] expectedLambda = { 1, 2, 6, 4, 6 };

        for (int i = 0; i < carmichaelNumbers.Length; i++)
        {
            int n = carmichaelNumbers[i];

            Console.WriteLine($"lambda({n}): {NumberTheory.Carmichael(n)}; " + $"ожидается {expectedLambda[i]}");
        }
    }
}