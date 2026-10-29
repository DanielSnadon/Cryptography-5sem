using System.Numerics;

namespace CryptoLab2;

public class SolovayStrassenTest : PrimeTest
{
    protected override bool TestOnce(BigInteger n, BigInteger a)
    {
        int symbol = HelperFuncs.JacobiSymbol(a, n);
        if (symbol == 0)
            return false;

        BigInteger right = symbol;

        if (right < 0)
            right += n;

        BigInteger left = HelperFuncs.ModPow(a, (n - 1) / 2, n);

        return left == right;
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