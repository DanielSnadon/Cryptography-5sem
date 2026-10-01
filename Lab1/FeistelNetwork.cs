namespace CryptoLab1;

public class FeistelNetwork : IBlockCipher
{
    private readonly IKeyExpansion keyExpansion;
    private readonly IRoundFunction roundFunction;
    private byte[][]? roundKeys;

    public int BlockSizeBytes { get; }

    public FeistelNetwork(
        IKeyExpansion keyExpansion,
        IRoundFunction roundFunction,
        int blockSizeBytes)
    {
        if (keyExpansion == null)
            throw new ArgumentNullException(nameof(keyExpansion));

        if (roundFunction == null)
            throw new ArgumentNullException(nameof(roundFunction));

        if (blockSizeBytes <= 0 || blockSizeBytes % 2 != 0)
            throw new ArgumentException(
                "Размер блока должен быть положительным и делиться на два.");

        this.keyExpansion = keyExpansion;
        this.roundFunction = roundFunction;
        BlockSizeBytes = blockSizeBytes;
    }

    public void SetKey(byte[] key)
    {
        if (key == null)
            throw new ArgumentNullException(nameof(key));

        roundKeys = keyExpansion.GenerateRoundKeys(key);

        if (roundKeys.Length == 0)
            throw new InvalidOperationException(
                "Расширение ключа не вернуло раундовых ключей.");
    }
}