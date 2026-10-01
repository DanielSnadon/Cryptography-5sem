namespace CryptoLab1;

public class DesKeyExpansion : IKeyExpansion
{
    private static readonly int[] pc1 =
    {
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    };

    private static readonly int[] pc2 =
    {
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    };

    private static readonly int[] leftShifts = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

    public byte[][] GenerateRoundKeys(byte[] masterKey)
    {
        if (masterKey == null) throw new ArgumentNullException("Ошибка GenerateRoundKeys: masterKey не может быть null.");

        if (masterKey.Length != 8) throw new ArgumentException("Ошибка GenerateRoundKeys: masterKey должен содержать ровно 8 байт.");

        byte[] currentKey = BitPermutation.Permutate(masterKey, pc1, true, 1);

        byte[][] roundKeys = new byte[16][];

        for (int round = 0; round < 16; round++)
        {
            currentKey = ShiftLeft(currentKey, leftShifts[round]);
            roundKeys[round] = BitPermutation.Permutate(currentKey, pc2, true, 1);
        }

        return roundKeys;
    }

    private static byte[] ShiftLeft(byte[] key56, int shift)
    {
        int[] rotationTable = new int[56];

        for (int i = 0; i < 28; i++)
        {
            rotationTable[i] = ((i + shift) % 28) + 1;
            rotationTable[i + 28] = 28 + ((i + shift) % 28) + 1;
        }

        return BitPermutation.Permutate(key56, rotationTable, true, 1);
    }
}