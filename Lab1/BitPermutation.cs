namespace CryptoLab1;

public static class BitPermutation
{
    public static byte[] Permutate(byte[] input, int[] pblock, bool olderFirst, int firstBit)
    {
        if (input == null) throw new ArgumentNullException("Ошибка BitPermutation: значение = null.");
        if (pblock == null) throw new ArgumentNullException("Ошибка BitPermutation: Р-блок = null.");
        if (firstBit != 0 && firstBit != 1) throw new ArgumentException("Ошибка BitPermutation: первый бит должен быть 0 или 1.");

        int inputBitCount = input.Length * 8;
        byte[] result = new byte[(pblock.Length + 7) / 8];

        for (int i = 0; i < pblock.Length; i++)
        {
            int bitIndex = pblock[i] - firstBit;

            if (bitIndex < 0 || bitIndex >= inputBitCount) throw new ArgumentOutOfRangeException("Ошибка BitPermutation: некорректный P-блок.");

            int inputByte = bitIndex / 8;
            int bitInsideByte = bitIndex % 8;

            int inputShift = olderFirst ? 7 - bitInsideByte : bitInsideByte;

            int bit = (input[inputByte] >> inputShift) & 1;

            int outputByte = i / 8;
            int outputShift = 7 - (i % 8);

            result[outputByte] |= (byte)(bit << outputShift);
        }

        return result;
    }
}