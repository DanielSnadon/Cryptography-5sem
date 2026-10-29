using System.Numerics;

namespace CryptoLab2;

public interface IPrimeTest
{
    bool IsPrime(BigInteger n, double probability);
}