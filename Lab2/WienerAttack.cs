using System;
using System.Collections.Generic;
using System.Numerics;

namespace CryptoLab2;

public static class WienerAttack
{
    public static List<(BigInteger numerator, BigInteger denominator)> ChainFunc(BigInteger numerator, BigInteger denominator)
    {
        if (numerator < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(numerator), "Ошибка ChainFunc: числитель не может быть отрицательным.");
        }
        if (denominator <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(denominator), "Ошибка ChainFunc: знаменатель должен быть положительным.");
        }
            
        var result = new List<(BigInteger numerator, BigInteger denominator)>();

        BigInteger oldNumerator = 0;
        BigInteger prevNumerator = 1;
        BigInteger oldDenominator = 1;
        BigInteger prevDenominator = 0;

        while (denominator != 0)
        {
            BigInteger part = numerator / denominator;

            BigInteger nextNumerator = part * prevNumerator + oldNumerator;
            BigInteger nextDenominator = part * prevDenominator + oldDenominator;

            result.Add((nextNumerator, nextDenominator));

            oldNumerator = prevNumerator;
            prevNumerator = nextNumerator;
            oldDenominator = prevDenominator;
            prevDenominator = nextDenominator;

            BigInteger remainder = numerator % denominator;
            numerator = denominator;
            denominator = remainder;
        }

        return result;
    }

    public static (bool found, BigInteger d, BigInteger phi, List<(BigInteger numerator, BigInteger denominator)> fractions) Attack(BigInteger n, BigInteger e)
    {
        if (n <= 1 || e <= 1)
        {
            throw new ArgumentException("Ошибка Attack: n и e должны быть больше единицы.");
        }

        var fractions = ChainFunc(e, n);

        foreach (var fraction in fractions)
        {
            BigInteger k = fraction.numerator;
            BigInteger d = fraction.denominator;

            if (k == 0)
                continue;

            // ed - 1 = k*phi(n)

            BigInteger value = e * d - 1;
            if (value % k != 0)
                continue;

            BigInteger phi = value / k;

            if (phi <= 0 || phi >= n)
                continue;

            // phi(n) = (p-1)(q-1)
            //      v v v
            // p + q = n - phi(n) + 1

            BigInteger sum = n - phi + 1;
            BigInteger discriminant = sum * sum - 4 * n;
            if (discriminant < 0)
                continue;
            BigInteger root = HelperFuncs.Sqrt(discriminant);
            if (root * root != discriminant)
                continue;

            if ((sum + root) % 2 != 0)
                continue;

            BigInteger p = (sum + root) / 2;
            BigInteger q = (sum - root) / 2;
            if (p <= 1 || q <= 1 || p == q || p * q != n)
                continue;

            return (true, d, phi, fractions);
        }
        return (false, 0, 0, fractions);
    }    
}