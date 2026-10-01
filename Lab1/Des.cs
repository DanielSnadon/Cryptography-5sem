namespace CryptoLab1;

public class Des : IBlockCipher
{
    public int BlockSizeBytes => 8;
    private FeistelNetwork feistelNetwork;
    private static readonly int[] initialPermutation =
    {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };
    private static readonly int[] finalPermutation =
    {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    };

    public Des()
    {
        feistelNetwork = new FeistelNetwork(
            new DesKeyExpansion(),
            new DesRoundFunction(),
            BlockSizeBytes);
    }

    public void SetKey(byte[] key)
    {
        feistelNetwork.SetKey(key);
    }

    public byte[] EncryptBlock(byte[] block)
    {
        ValidateBlock(block);

        byte[] blockAfterIP = BitPermutation.Permutate(block, initialPermutation, olderFirst: true, firstBit: 1);

        byte[] blockBeforeFinalIP = feistelNetwork.EncryptBlock(blockAfterIP);

        return BitPermutation.Permutate(blockBeforeFinalIP, finalPermutation, olderFirst: true, firstBit: 1);
    }

    public byte[] DecryptBlock(byte[] block)
    {
        ValidateBlock(block);

        byte[] blockBeforeFeistel = BitPermutation.Permutate(block, initialPermutation, olderFirst: true, firstBit: 1);

        byte[] blockAfterFeistel = feistelNetwork.DecryptBlock(blockBeforeFeistel);

        return BitPermutation.Permutate(blockAfterFeistel, finalPermutation, olderFirst: true, firstBit: 1);
    }

    private void ValidateBlock(byte[] block)
    {
        if (block == null) throw new ArgumentNullException("Ошибка Des: блок не может быть null.");
        if (block.Length != BlockSizeBytes) throw new ArgumentException("Ошибка Des: блок должен занимать ровно 8 байт.");
    }
}