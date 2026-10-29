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

    public static (BigInteger gcd, BigInteger x, BigInteger y) ExtGcd(BigInteger a, BigInteger b)
    {
        BigInteger prevOst = a;
        BigInteger currOst = b;

        BigInteger prevX = 1;
        BigInteger prevY = 0;
        BigInteger currX = 0;
        BigInteger currY = 1;

        while (currOst != 0)
        {
            BigInteger celayaChast = prevOst / currOst;
            BigInteger nextOst = prevOst - celayaChast * currOst;
            BigInteger nextX = prevX - celayaChast * currX;
            BigInteger nextY = prevY - celayaChast * currY;

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

    public static BigInteger BinaryGcd(BigInteger a, BigInteger b)
    {
        if (a < 0)
            a = -a;
        if (b < 0)
            b = -b;

        if (a == 0)
            return b;
        if (b == 0)
            return a;

        BigInteger dvoiki = 1;

        while (a % 2 == 0 && b % 2 == 0)
        {
            a >>= 1;
            b >>= 1;
            dvoiki <<= 1;
        }

        while (a % 2 == 0)
            a >>= 1;

        while (b != 0)
        {
            while (b % 2 == 0)
                b >>= 1;
            if (a > b)
            {
                BigInteger temp = a;
                a = b;
                b = temp;
            }
            b -= a;
        }

        return a * dvoiki;
    }

    public static BigInteger ModPow(BigInteger value, BigInteger exponent, BigInteger modulus)
    {
        if (exponent < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(exponent), "Ошибка ModPow: показатель степени не может быть отрицательным.");
        }
        if (modulus <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(modulus), "Ошибка ModPow: модуль должен быть положительным.");
        }

        value %= modulus;

        if (value < 0)
            value += modulus;

        BigInteger result = 1 % modulus;

        while (exponent > 0)
        {
            if (exponent % 2 != 0)
                result = (result * value) % modulus;

            value = (value * value) % modulus;

            exponent >>= 1;
        }

        return result;
    }

    public static int LegendreSymbol(BigInteger a, BigInteger p)
    {
        if (p < 3 || p % 2 == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(p), "Ошибка LegendreSymbol: p должно быть нечётным простым числом.");
        }

        BigInteger result = ModPow(a, (p - 1) / 2, p);

        if (result == 0)
            return 0;
        if (result == 1)
            return 1;
        if (result == p - 1)
            return -1;

        throw new ArgumentException("Ошибка LegendreSymbol: p - простое число.", nameof(p));
    }

    public static int JacobiSymbol(BigInteger a, BigInteger n)
    {
        if (n <= 0 || n % 2 == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(n), "Ошибка JacobiSymbol: n должно быть положительным нечётным числом.");
        }

        a %= n;
        if (a < 0)
            a += n;
        int sign = 1;

        while (a != 0)
        {
            while (a % 2 == 0)
            {
                a >>= 1;

                BigInteger remainder = n % 8;

                if (remainder == 3 || remainder == 5)
                    sign = -sign;
            }

            if (a % 4 == 3 && n % 4 == 3)
                sign = -sign;

            BigInteger temp = a;
            a = n;
            n = temp;

            a %= n;
        }

        return n == 1 ? sign : 0;
    }

    public static BigInteger EulerBasic(BigInteger n)
    {
        if (n <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(n), "Ошибка EulerBasic: n должно быть положительным.");
        }

        BigInteger count = 0;

        for (BigInteger k = 1; k <= n; k++)
        {
            if (Gcd(k, n) == 1)
                count++;
        }

        return count;
    }

    public static BigInteger EulerFactorization(BigInteger n)
    {
        if (n <= 0) throw new ArgumentOutOfRangeException(nameof(n), "Ошибка EulerFactorization: n должно быть положительным.");

        BigInteger result = n;
        BigInteger remaining = n;

        for (BigInteger divisor = 2; divisor * divisor <= remaining; divisor++)
        {
            if (remaining % divisor != 0)
                continue;

            // result * (1 - 1/divisor) = result - result/divisor.
            result -= result / divisor;

            while (remaining % divisor == 0)
                remaining /= divisor;
        }

        if (remaining > 1)
            result -= result / remaining;

        return result;
    }

    public static BigInteger EulerFourier(int n)
    {
        if (n <= 0) 
        {
            throw new ArgumentOutOfRangeException(nameof(n), "Ошибка EulerFourier: n должно быть положительным.");
        }

        double sum = 0;

        for (long k = 1; k <= n; k++)
        {
            double gcd = (double)Gcd(k, n);
            double angle = 2.0 * Math.PI * k / n;
            sum += gcd * Math.Cos(angle);
        }

        return new BigInteger(Math.Round(sum));
    }

    private static BigInteger Nok(BigInteger a, BigInteger b)
    {
        return a / Gcd(a, b) * b;
    }

    public static BigInteger Carmichael(BigInteger n)
    {
        if (n <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(n), "Ошибка Carmichael: n должно быть положительным.");
        }

        BigInteger result = 1;
        BigInteger remaining = n;

        for (BigInteger divisor = 2; divisor * divisor <= remaining; divisor++)
        {
            if (remaining % divisor != 0)
                continue;

            BigInteger power = 1;

            while (remaining % divisor == 0)
            {
                remaining /= divisor;
                power *= divisor;
            }

            BigInteger component = (power / divisor) * (divisor - 1);

            if (divisor == 2 && power >= 8)
                component /= 2;

            result = Nok(result, component);
        }

        if (remaining > 1)
            result = Nok(result, remaining - 1);

        return result;
    }
}