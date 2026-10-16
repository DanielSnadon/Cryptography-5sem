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

    public static (BigInteger gcd, BigInteger x, BigInteger y)
    ExtGcd(BigInteger a, BigInteger b)
{
    // _ = ax + by
    BigInteger prevOst = a;
    BigInteger currOst = b;

    BigInteger prevX = 1;
    BigInteger prevY = 0;
    BigInteger currX = 0;
    BigInteger currY = 1;

    while (currOst != 0)
    {
        BigInteger temp = prevOst / currOst;
        BigInteger nextOst = prevOst - temp * currOst;
        BigInteger nextX = prevX - temp * currX;
        BigInteger nextY = prevY - temp * currY;

        prevOst = currOst;
        prevX = currX;
        prevY = currY;

        currOst = nextOst;
        currX = nextX;
        currY = nextY;
    }

    if (prevOst < 0)
    {
        prevOst = -prevOst;
        prevX = -prevX;
        prevY = -prevY;
    }

    return (prevOst, prevX, prevY);
}
}