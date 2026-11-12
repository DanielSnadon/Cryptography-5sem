using System;
using System.Collections.Generic;
using System.Numerics;

namespace CryptoLab3;

public sealed class HelperFuncs
{
    public byte Add(byte left, byte right)
    {
        return (byte)(left ^ right);
    }

    private static int Remainder(int number, int divisor, int divisorDegree)
    {
        for (int degree = 8; degree >= divisorDegree; degree--)
        {
            if ((number & (1 << degree)) != 0)
                number ^= divisor << (degree - divisorDegree);
        }

        return number;
    }

    public bool IrreducibleCheck(byte modulus)
    {
        int polynomial = 0x100 | modulus;

        for (int degree = 1; degree <= 4; degree++)
        {
            int leadingBit = 1 << degree;

            for (int divisor = leadingBit; divisor < (leadingBit << 1); divisor++)
            {
                if (Remainder(polynomial, divisor, degree) == 0)
                    return false;
            }
        }

        return true;
    }

    public byte Multiply(byte left, byte right, byte modulus)
    {
        if (!IrreducibleCheck(modulus))
        {
            throw new ArgumentException("Ошибка multiply: полином-модуль приводим.");
        }

        int result = 0;
        int leftNum = left;
        int rightNum = right;
        int polynomial = 0x100 | modulus;

        while (rightNum != 0)
        {
            if ((rightNum & 1) != 0)
                result ^= leftNum;

            rightNum >>= 1;
            leftNum <<= 1;

            if ((leftNum & 0x100) != 0)
                leftNum ^= polynomial;
        }

        return (byte)result;
    }

    public List<byte> GetIreducibles()
    {
        var answer = new List<byte>();

        for (int candidate = 0; candidate <= byte.MaxValue; candidate++)
        {
            byte modulus = (byte)candidate;

            if (IrreducibleCheck(modulus))
                answer.Add(modulus);
        }

        return answer;
    }

    public byte Inverse(byte value, byte modulus)
    {
        if (!IrreducibleCheck(modulus))
        {
            throw new ArgumentException("Ошибка inverse: полином-модуль приводим.");
        }

        if (value == 0)
            throw new ArgumentException("Ошибка inverse: у нуля нет обратного элемента.");

        byte result = 1;
        byte power = value;
        int exponent = 254;

        while (exponent != 0)
        {
            if ((exponent & 1) != 0)
                result = Multiply(result, power, modulus);

            exponent >>= 1;

            if (exponent != 0)
                power = Multiply(power, power, modulus);
        }

        return result;
    }

    private static int Degree(BigInteger polynomial)
    {
        int degree = -1;

        while (polynomial > BigInteger.Zero)
        {
            polynomial >>= 1;
            degree++;
        }

        return degree;
    }

    private static (BigInteger Answer, BigInteger Remainder) DividePolynoms(BigInteger number, BigInteger divisor)
    {
        if (divisor == BigInteger.Zero)
            throw new DivideByZeroException("Ошибка dividePolynoms: некорректный делитель.");

        BigInteger answer = BigInteger.Zero;
        BigInteger remainder = number;
        int divisorDegree = Degree(divisor);

        for (int degree = Degree(number); degree >= divisorDegree; degree--)
        {
            if ((remainder & (BigInteger.One << degree)) == BigInteger.Zero)
                continue;

            int shift = degree - divisorDegree;

            answer |= BigInteger.One << shift;
            remainder ^= divisor << shift;
        }

        return (answer, remainder);
    }

    public List<BigInteger> Factorize(BigInteger polynomial)
    {
        if (polynomial <= BigInteger.Zero)
        {
            throw new ArgumentOutOfRangeException("Ошибка factorize: битовая запись полинома должна быть положительной.");
        }

        var factors = new List<BigInteger>();
        BigInteger remaining = polynomial;

        for (int degree = 1; degree <= Degree(remaining) / 2; degree++)
        {
            BigInteger first = BigInteger.One << degree;
            BigInteger last = first << 1;

            for (BigInteger candidate = first; candidate < last; candidate++)
            {
                while (true)
                {
                    var (quotient, remainder) = DividePolynoms(remaining, candidate);

                    if (remainder != BigInteger.Zero)
                        break;

                    factors.Add(candidate);
                    remaining = quotient;
                }
            }
        }

        if (remaining != BigInteger.One)
            factors.Add(remaining);

        return factors;
    }
}