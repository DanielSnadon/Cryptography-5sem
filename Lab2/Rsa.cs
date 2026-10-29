using System;
using System.Numerics;

namespace CryptoLab2;

public class Rsa
{
    public enum TestType
    {
        Fermat,
        SolovayStrassen,
        MillerRabin
    }

    private readonly KeyGenerator generator;

    public Rsa(TestType testType, double probability, int bitLength)
    {
        generator = new KeyGenerator(testType, probability, bitLength);
    }

    public void GenerateKeys()
    {
        var keys = generator.Generate();

        n = keys.n;
        e = keys.e;
        d = keys.d;

        hasKey = true;
    }

    public (BigInteger n, BigInteger e) GetPublicKey()
    {
        if (!hasKey)
        {
            throw new InvalidOperationException("Ошибка GetPublicKey: ключей нет.");
        }

        return (n, e);
    }

    private BigInteger n;
    private BigInteger e;
    private BigInteger d;

    private bool hasKey;

    private class KeyGenerator
    {
        private readonly IPrimeTest test;
        private readonly double probability;
        private readonly int bitLength;

        public KeyGenerator(TestType testType, double probability, int bitLength)
        {
            if (double.IsNaN(probability) || probability < 0.5 || probability >= 1)
            {
                throw new ArgumentOutOfRangeException(nameof(probability), "Ошибка KeyGenerator: неверно заданная probability.");
            }
            if (bitLength < 3)
            {
                throw new ArgumentOutOfRangeException(nameof(bitLength), "Ошибка KeyGenerator: битовая длина должна быть не меньше 3.");
            }

            switch (testType)
            {
                case TestType.Fermat:
                    test = new FermatTest();
                    break;
                case TestType.SolovayStrassen:
                    test = new SolovayStrassenTest();
                    break;
                case TestType.MillerRabin:
                    test = new MillerRabinTest();
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(testType), "Ошибка KeyGenerator: неизвестный тест простоты.");
            }

            this.probability = probability;
            this.bitLength = bitLength;
        }

        private BigInteger RandomCandidate()
        {
            BigInteger min = BigInteger.One << (bitLength - 1);
            BigInteger messenger = (BigInteger.One << bitLength) - 1;
            BigInteger candidate = HelperFuncs.RandomNumber(min, messenger);

            if (candidate % 2 == 0)
                candidate++;

            return candidate;
        }

        private BigInteger RandomPrime()
        {
            while (true)
            {
                BigInteger candidate = RandomCandidate();

                if (test.IsPrime(candidate, probability))
                    return candidate;
            }
        }

        private (BigInteger p, BigInteger q) RandomPrimes()
        {
            BigInteger minDifference = BigInteger.One << (bitLength - 3);

            while (true)
            {
                BigInteger p = RandomPrime();
                BigInteger q = RandomPrime();
                if (p == q)
                    continue;

                BigInteger difference = p - q;

                if (difference < 0)
                    difference = -difference;
                if (difference < minDifference) // От Ферма
                    continue;

                return (p, q);
            }
        }

        public (BigInteger n, BigInteger e, BigInteger d) Generate()
        {
            while (true)
            {
                var primes = RandomPrimes();

                BigInteger p = primes.p;
                BigInteger q = primes.q;
                BigInteger n = p * q;
                BigInteger phi = (p - 1) * (q - 1);

                BigInteger e = 65537;
                if (e >= phi)
                    e = HelperFuncs.RandomNumber(3, phi - 1);

                if (HelperFuncs.Gcd(e, phi) != 1)
                    continue;

                BigInteger d = HelperFuncs.Inverse(e, phi);

                if (d * d <= n) // От Винера
                    continue;

                return (n, e, d);
            }
        }
    }

    public BigInteger Encrypt(BigInteger data)
    {
        if (!hasKey)
        {
            throw new InvalidOperationException("Ошибка Encrypt: ключей нет.");
        }
        if (data < 0 || data >= n)
        {
            throw new ArgumentOutOfRangeException(nameof(data), "Ошибка Encrypt: некорректное число.");
        }
        return HelperFuncs.ModPow(data, e, n);
    }

    public BigInteger Decrypt(BigInteger data)
    {
        if (!hasKey)
        {
            throw new InvalidOperationException("Ошибка Encrypt: ключей нет.");
        }
        if (data < 0 || data >= n)
        {
            throw new ArgumentOutOfRangeException(nameof(data), "Ошибка Encrypt: некорректное число.");
        }

        return HelperFuncs.ModPow(data, d, n);
    }
}