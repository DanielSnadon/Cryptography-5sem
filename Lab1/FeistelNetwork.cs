namespace CryptoLab1;

public class FeistelNetwork : IBlockCipher
{
    private readonly IKeyExpansion keyExpansion;
    private readonly IRoundFunction roundFunction;
    private byte[][]? roundKeys;

    public int BlockSizeBytes { get; }

    public FeistelNetwork(IKeyExpansion keyExpansion, IRoundFunction roundFunction, int blockSizeBytes)
    {
        if (keyExpansion == null) throw new ArgumentNullException("Ошибка конструктора FeistelNetwork: keyExpansion не может быть null.");

        if (roundFunction == null) throw new ArgumentNullException("Ошибка конструктора FeistelNetwork: roundFunction не может быть null.");

        if (blockSizeBytes <= 0 || blockSizeBytes % 2 != 0) throw new ArgumentException("Ошибка конструктора FeistelNetwork: некорректный размер блока.", nameof(blockSizeBytes));

        this.keyExpansion = keyExpansion;
        this.roundFunction = roundFunction;
        BlockSizeBytes = blockSizeBytes;
    }

    public void SetKey(byte[] key)
    {
        if (key == null) throw new ArgumentNullException("Ошибка SetKey: ключ не может быть null.");

        roundKeys = keyExpansion.GenerateRoundKeys(key);

        if (roundKeys.Length == 0) throw new InvalidOperationException("Ошибка SetKey: расширение ключа не вернуло раундовых ключей.");
    }

    public byte[] EncryptBlock(byte[] block)
    {
        ValidateBlock(block);

        if (roundKeys == null) throw new InvalidOperationException("Ошибка EncryptBlock: сначала нужно установить ключ.");

        int halfSize = BlockSizeBytes / 2;

        byte[] left = new byte[halfSize];
        byte[] right = new byte[halfSize];

        Array.Copy(block, 0, left, 0, halfSize);
        Array.Copy(block, halfSize, right, 0, halfSize);

        for (int i = 0; i < roundKeys.Length; i++)
        {
            byte[] fResult = roundFunction.RoundFunc(right, roundKeys[i]);
            byte[] nextRight = XorBlocks(left, fResult);

            left = right;
            right = nextRight;
        }

        return JoinBlocks(right, left);
    }

    public byte[] DecryptBlock(byte[] block)
    {
        ValidateBlock(block);

        if (roundKeys == null) throw new InvalidOperationException("Ошибка DecryptBlock: сначала нужно установить ключ.");

        int halfSize = BlockSizeBytes / 2;

        byte[] left = new byte[halfSize];
        byte[] right = new byte[halfSize];

        Array.Copy(block, halfSize, left, 0, halfSize);
        Array.Copy(block, 0, right, 0, halfSize);

        for (int i = roundKeys.Length - 1; i >= 0; i--)
        {
            byte[] fResult = roundFunction.RoundFunc(left, roundKeys[i]);
            byte[] previousLeft = XorBlocks(right, fResult);

            right = left;
            left = previousLeft;
        }

        return JoinBlocks(left, right);
    }

    private void ValidateBlock(byte[] block)
    {
        if (block == null) throw new ArgumentNullException("Ошибка ValidateBlock: блок не может быть null.");

        if (block.Length != BlockSizeBytes) throw new ArgumentException("Ошибка ValidateBlock: неверный размер блока.");
    }

    private static byte[] XorBlocks(byte[] first, byte[] second)
    {
        if (first.Length != second.Length) throw new ArgumentException("Ошибка XorBlocks: XOR-блоки должны иметь одинаковую длину.");

        byte[] result = new byte[first.Length];

        for (int i = 0; i < first.Length; i++)
            result[i] = (byte)(first[i] ^ second[i]);

        return result;
    }

    private static byte[] JoinBlocks(byte[] first, byte[] second)
    {
        byte[] result = new byte[first.Length + second.Length];

        Array.Copy(first, 0, result, 0, first.Length);
        Array.Copy(second, 0, result, first.Length, second.Length);

        return result;
    }
}