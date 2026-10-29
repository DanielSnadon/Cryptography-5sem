using System.Numerics;

namespace CryptoLab2;

public class FermatTest : PrimeTest
{
    protected override bool TestOnce(BigInteger n, BigInteger a)
    {
        return HelperFuncs.ModPow(a, n - 1, n) == 1;
    }

    protected override int GetRounds(double probability)
    {
        int rounds = 0;
        double error = 1;

        while (error > 1 - probability)
        {
            error *= 0.5;
            rounds++;
        }

        return rounds;
    }
}