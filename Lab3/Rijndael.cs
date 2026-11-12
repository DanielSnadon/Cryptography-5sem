using System;

namespace CryptoLab3;

public sealed class Rijndael
{
    private readonly byte modulus;
    private readonly HelperFuncs funcs = new();
    public int BlockSizeBytes { get; }
    private readonly Lazy<byte[]> forwardSBox;
    private readonly Lazy<byte[]> inverseSBox;
    private byte[][]? roundKeys;

    public Rijndael(int blockSizeBits, byte modulus = 0x1B)
    {
        if (blockSizeBits != 128 && blockSizeBits != 192 && blockSizeBits != 256)
        {
            throw new ArgumentOutOfRangeException("Ошибка создания rijndael: размер блока должен быть 128, 192 или 256 бит.");
        }
        if (!funcs.IrreducibleCheck(modulus))
        {
            throw new ArgumentException("Ошибка создания rijndael: полином-модуль приводим.");
        }

        BlockSizeBytes = blockSizeBits / 8;
        forwardSBox = new Lazy<byte[]>(BuildForwardSBox);
        inverseSBox = new Lazy<byte[]>(BuildInverseSBox);
        this.modulus = modulus;
    }

    // {{{ SP-NET }}}

    private byte[] BuildForwardSBox()
    {
        var table = new byte[256];

        table[0] = 0x63;

        for (int input = 1; input < table.Length; input++)
        {
            byte inverse = funcs.Inverse((byte)input, modulus);
            table[input] = (byte)(inverse ^ RotateLeftByte(inverse, 1) ^ RotateLeftByte(inverse, 2) ^ RotateLeftByte(inverse, 3) ^ RotateLeftByte(inverse, 4) ^ 0x63);
        }

        return table;
    }

    private static byte RotateLeftByte(byte value, int shift)
    {
        int shifted = (value << shift) & 0xFF;
        int wrapped = value >> (8 - shift);

        return (byte)(shifted | wrapped);
    }

    private void SubBytes(Span<byte> state)
    {
        byte[] table = forwardSBox.Value;

        for (int i = 0; i < state.Length; i++)
            state[i] = table[state[i]];
    }

    private byte[] BuildInverseSBox()
    {
        var table = new byte[256];

        for (int input = 0; input < table.Length; input++)
        {
            byte value = (byte)input;

            byte beforeAffine = (byte)(
                RotateLeftByte(value, 1)
                ^ RotateLeftByte(value, 3)
                ^ RotateLeftByte(value, 6)
                ^ 0x05);

            // Прямая замена обрабатывает ноль отдельно.
            table[input] = beforeAffine == 0
                ? (byte)0
                : funcs.Inverse(beforeAffine, modulus);
        }

        return table;
    }

    private void InvSubBytes(byte[] state)
    {
        byte[] table = inverseSBox.Value;

        for (int i = 0; i < state.Length; i++)
            state[i] = table[state[i]];
    }

    private void ShiftRows(byte[] state)
    {
        ShiftRowsCore(state, inverse: false);
    }

    private void InvShiftRows(byte[] state)
    {
        ShiftRowsCore(state, inverse: true);
    }

    private void ShiftRowsCore(byte[] state, bool inverse)
    {
        int columns = BlockSizeBytes / 4;
        int[] shifts = columns == 8 ? new[] { 0, 1, 3, 4 } : new[] { 0, 1, 2, 3 };

        var original = (byte[])state.Clone();

        for (int row = 1; row < 4; row++)
        {
            int shift = shifts[row];
            int offset = inverse ? columns - shift : shift;

            for (int column = 0; column < columns; column++)
            {
                int sourceColumn = (column + offset) % columns;

                state[4 * column + row] = original[4 * sourceColumn + row];
            }
        }
    }

    private void MixColumns(byte[] state)
    {
        for (int offset = 0; offset < state.Length; offset += 4)
        {
            byte a0 = state[offset];
            byte a1 = state[offset + 1];
            byte a2 = state[offset + 2];
            byte a3 = state[offset + 3];

            byte twice0 = funcs.Multiply(0x02, a0, modulus);
            byte twice1 = funcs.Multiply(0x02, a1, modulus);
            byte twice2 = funcs.Multiply(0x02, a2, modulus);
            byte twice3 = funcs.Multiply(0x02, a3, modulus);

            byte triple0 = (byte)(twice0 ^ a0);
            byte triple1 = (byte)(twice1 ^ a1);
            byte triple2 = (byte)(twice2 ^ a2);
            byte triple3 = (byte)(twice3 ^ a3);

            state[offset]     = (byte)(twice0 ^ triple1 ^ a2 ^ a3);
            state[offset + 1] = (byte)(a0 ^ twice1 ^ triple2 ^ a3);
            state[offset + 2] = (byte)(a0 ^ a1 ^ twice2 ^ triple3);
            state[offset + 3] = (byte)(triple0 ^ a1 ^ a2 ^ twice3);
        }
    }

    private static readonly byte[,] inverseMixMatrix =
    {
        { 0x0E, 0x0B, 0x0D, 0x09 },
        { 0x09, 0x0E, 0x0B, 0x0D },
        { 0x0D, 0x09, 0x0E, 0x0B },
        { 0x0B, 0x0D, 0x09, 0x0E }
    };
    private void InvMixColumns(byte[] state)
    {
        Span<byte> originalColumn = stackalloc byte[4];

        for (int offset = 0; offset < state.Length; offset += 4)
        {
            state.AsSpan(offset, 4).CopyTo(originalColumn);

            for (int row = 0; row < 4; row++)
            {
                byte result = 0;

                for (int inputRow = 0; inputRow < 4; inputRow++)
                {
                    byte coefficient = inverseMixMatrix[row, inputRow];
                    result ^= funcs.Multiply(coefficient, originalColumn[inputRow], modulus);
                }

                state[offset + row] = result;
            }
        }
    }

    private static void AddRoundKey(byte[] state, byte[] roundKey)
    {
        for (int i = 0; i < state.Length; i++)
            state[i] ^= roundKey[i];
    }

    // {{{{ Key Expansion }}}}

    private static void RotWord(Span<byte> word)
    {
        byte first = word[0];

        word[0] = word[1];
        word[1] = word[2];
        word[2] = word[3];
        word[3] = first;
    }

    private void SubWord(Span<byte> word)
    {
        SubBytes(word);
    }

    private byte[][] ExpandKey(byte[] key)
    {
        if (key is null)
        {
            throw new ArgumentNullException("Ошибка expandKey: некорректный ключ.");
        }

        if (key.Length != 16 && key.Length != 24 && key.Length != 32)
        {
            throw new ArgumentException("Ошибка expandKey: длина ключа должна быть 16, 24 или 32 байта.");
        }

        int blockWords = BlockSizeBytes / 4;
        int keyWords = key.Length / 4;
        int rounds = Math.Max(blockWords, keyWords) + 6;
        int totalWords = blockWords * (rounds + 1);

        var expanded = new byte[4 * totalWords];
        key.AsSpan().CopyTo(expanded);
        Span<byte> word = stackalloc byte[4];

        byte rCon = 0x01;

        for (int wordIndex = keyWords; wordIndex < totalWords; wordIndex++)
        {
            int offset = 4 * wordIndex;
            expanded.AsSpan(offset - 4, 4).CopyTo(word);

            if (wordIndex % keyWords == 0)
            {
                RotWord(word);
                SubWord(word);
                word[0] ^= rCon;
                rCon = funcs.Multiply(rCon, 0x02, modulus);
            }
            else if (keyWords == 8 && wordIndex % keyWords == 4)
            {
                SubWord(word);
            }

            int earlierOffset = 4 * (wordIndex - keyWords);

            for (int j = 0; j < 4; j++)
                expanded[offset + j] = (byte)(expanded[earlierOffset + j] ^ word[j]);
        }

        var keys = new byte[rounds + 1][];

        for (int round = 0; round < keys.Length; round++)
        {
            int offset = round * BlockSizeBytes;
            keys[round] = expanded.AsSpan(offset, BlockSizeBytes).ToArray();
        }

        return keys;
    }

    public void SetKey(byte[] key)
    {
        roundKeys = ExpandKey(key);
    }

    // {{{ Main funcs }}}

    public byte[] EncryptBlock(byte[] inputBlock)
    {
        if (inputBlock is null)
        {
            throw new ArgumentNullException("Ошибка encryptBlock: тупой input.");
        }
        if (inputBlock.Length != BlockSizeBytes)
        {
            throw new ArgumentException($"Ошибка encryptBlock: блок должен содержать ровно {BlockSizeBytes} байт.");
        }
        byte[][] keys = roundKeys ?? throw new InvalidOperationException("Ошибка encryptBlock: вызови SetKey.");

        byte[] state = (byte[])inputBlock.Clone();
        int lastRound = keys.Length - 1;

        AddRoundKey(state, keys[0]);

        for (int round = 1; round < lastRound; round++)
        {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, keys[round]);
        }

        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, keys[lastRound]);

        return state;
    }

    public byte[] DecryptBlock(byte[] inputBlock)
    {
        if (inputBlock is null)
        {
            throw new ArgumentNullException("Ошибка encryptBlock: тупой input.");
        }
        if (inputBlock.Length != BlockSizeBytes)
        {
            throw new ArgumentException($"Ошибка encryptBlock: блок должен содержать ровно {BlockSizeBytes} байт.");
        }
        byte[][] keys = roundKeys ?? throw new InvalidOperationException("Ошибка encryptBlock: вызови SetKey.");

        byte[] state = (byte[])inputBlock.Clone();
        int lastRound = keys.Length - 1;

        AddRoundKey(state, keys[lastRound]);
        InvShiftRows(state);
        InvSubBytes(state);

        for (int round = lastRound - 1; round >= 1; round--)
        {
            AddRoundKey(state, keys[round]);
            InvMixColumns(state);
            InvShiftRows(state);
            InvSubBytes(state);
        }

        AddRoundKey(state, keys[0]);

        return state;
    }
}