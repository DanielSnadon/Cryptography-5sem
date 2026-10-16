using System.Numerics;

namespace CryptoLab2;

public static class HelperFuncs
{
    public static BigInteger Gcd(BigInteger a, BigInteger b)
    {
        if (a < 0)
            a = -a;
        if (b < 0)
            b = -b;

        while (b != 0)
        {
            BigInteger ost = a % b;
            
            a = b;
            b = ost;
        }

        return a;
    }
}