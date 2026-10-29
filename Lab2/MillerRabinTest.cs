using System.Numerics;

namespace CryptoLab2;

public class MillerRabinTest : PrimeTest
{
    protected override bool TestOnce(BigInteger n, BigInteger a)
    {
        BigInteger d = n - 1;
        int s = 0;
        
        while (d % 2 == 0)
        {
            d >>= 1;
            s++;
        }

        BigInteger x = HelperFuncs.ModPow(a, d, n);
        
        // a ^ d = x (mod n)
        // I
        if (x == 1 || x == n - 1)
            return true;

        // II
        for (int i = 1; i < s; i++)
        {
            x = (x * x) % n;
            if (x == n - 1)
                return true;
        }

        return false;
    }

    protected override int GetRounds(double probability)
    {
        int rounds = 0;
        double error = 1;

        while (error > 1 - probability)
        {
            error *= 0.25;
            rounds++;
        }

        return rounds;
    }
}