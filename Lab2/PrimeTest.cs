using System;
using System.Numerics;

namespace CryptoLab2;

public abstract class PrimeTest : IPrimeTest
{
    public bool IsPrime(BigInteger n, double probability)
    {
        if (double.IsNaN(probability) || probability < 0.5 || probability >= 1)
        {
            throw new ArgumentOutOfRangeException(nameof(probability), "Ошибка IsPrime: неверное значение probability.");
        }

        if (n < 2)
            return false;
        if (n == 2 || n == 3)
            return true;
        if (n % 2 == 0)
            return false;

        int rounds = GetRounds(probability);

        for (int i = 0; i < rounds; i++)
        {
            BigInteger a = HelperFuncs.RandomNumber(2, n - 2);

            if (HelperFuncs.Gcd(a, n) != 1)
                return false;

            if (!TestOnce(n, a))
                return false;
        }

        return true;
    }

    protected abstract int GetRounds(double probability);

    protected abstract bool TestOnce(BigInteger n, BigInteger a);
}