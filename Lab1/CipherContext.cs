using System.IO.Compression;
using System.Security.Cryptography;

namespace CryptoLab1;

public class CipherContext
{
    private readonly IBlockCipher cipher;
    private readonly EncryptionMode encryptionMode;
    private readonly PaddingScheme paddingScheme;
    private readonly byte[]? initializationVector;
    private readonly object[]? additionalParameters;

    public CipherContext(IBlockCipher cipher, byte[] key, EncryptionMode encryptionMode, PaddingScheme paddingScheme, byte[]? initializationVector = null, params object[] additionalParameters)
    {
        if (cipher == null) throw new ArgumentNullException("Ошибка CipherContext: пустой объект шифра.");
        if (key == null) throw new ArgumentNullException("Ошибка CipherContext: пустой ключ.");

        this.cipher = cipher;
        this.encryptionMode = encryptionMode;
        this.paddingScheme = paddingScheme;
        this.initializationVector = initializationVector;
        this.additionalParameters = additionalParameters;

        this.cipher.SetKey(key);
    }

    private byte[] ApplyPadding(byte[] data)
    {
        if (data == null) throw new ArgumentNullException("Ошибка ApplyPadding: пустая data.");
        int blockSize = cipher.BlockSizeBytes;
        if (blockSize <= 0) throw new InvalidOperationException("Ошибка ApplyPadding: размер блока должен быть больше нуля.");

        int paddingLength = blockSize - data.Length % blockSize;

        if (paddingScheme == PaddingScheme.Zeros &&
            data.Length % blockSize == 0)
        {
            paddingLength = 0;
        }

        byte[] paddedData = new byte[data.Length + paddingLength];
        Array.Copy(data, paddedData, data.Length);

        switch (paddingScheme)
        {
            case PaddingScheme.Zeros:
                break;

            case PaddingScheme.AnsiX923:
                paddedData[paddedData.Length - 1] = (byte)paddingLength;
                break;

            case PaddingScheme.Pkcs7:
                for (int i = data.Length; i < paddedData.Length; i++)
                {
                    paddedData[i] = (byte)paddingLength;
                }
                break;

            case PaddingScheme.Iso10126:
                int randomByteCount = paddingLength - 1;
                byte[] randomBytes = new byte[randomByteCount];

                RandomNumberGenerator.Fill(randomBytes);

                Array.Copy(randomBytes, 0, paddedData, data.Length, randomByteCount);

                paddedData[paddedData.Length - 1] = (byte)paddingLength;
                break;

            default:
                throw new ArgumentOutOfRangeException("Ошибка ApplyPadding: неизвестный тип набивки.");
        }

        return paddedData;
    }

    private byte[] RemovePadding(byte[] data)
    {
        if (data == null) throw new ArgumentNullException("Ошибка RemovePadding: пустая data.");
        int blockSize = cipher.BlockSizeBytes;
        if (data.Length == 0 || data.Length % blockSize != 0) throw new FormatException("Ошибка RemovePadding: размер данных не соответствует размеру блока.");

        int paddingLength = 0;

        switch (paddingScheme)
        {
            case PaddingScheme.Zeros:
                while (paddingLength < data.Length &&
                    data[data.Length - 1 - paddingLength] == 0)
                {
                    paddingLength++;
                }
                break;

            case PaddingScheme.AnsiX923:
            case PaddingScheme.Pkcs7:
            case PaddingScheme.Iso10126:
                paddingLength = data[data.Length - 1];

                if (paddingLength < 1 || paddingLength > blockSize || paddingLength > data.Length)
                {
                    throw new FormatException("Ошибка RemovePadding: некорректная длина набивки.");
                }

                // What if...
                if (paddingScheme == PaddingScheme.Pkcs7)
                {
                    for (int i = data.Length - paddingLength; i < data.Length; i++)
                    {
                        if (data[i] != paddingLength)
                            throw new FormatException("Ошибка RemovePadding: некорректная набивка PKCS7.");
                    }
                }

                if (paddingScheme == PaddingScheme.AnsiX923)
                {
                    for (int i = data.Length - paddingLength; i < data.Length - 1; i++)
                    {
                        if (data[i] != 0)
                            throw new FormatException("Ошибка RemovePadding: некорректная набивка ANSI X.923.");
                    }
                }
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(paddingScheme));
        }

        byte[] unpaddedData = new byte[data.Length - paddingLength];
        Array.Copy(data, unpaddedData, unpaddedData.Length);

        return unpaddedData;
    }

    private byte[] GetIV(int blockSize)
    {
        if (initializationVector == null) throw new InvalidOperationException("Ошибка GetIV: initializationVector отсутствует.");
        if (initializationVector.Length != blockSize) throw new ArgumentException("Ошибка GetIV: длина IV должна совпадать с размером блока.");

        return (byte[])initializationVector.Clone();
    }

    private byte[] XorBlocks(byte[] first, byte[] second)
    {
        if (first.Length != second.Length) throw new ArgumentException("Ошибка XorBlocks: блоки должны быть одинаковой длины.");

        byte[] result = new byte[first.Length];

        for (int i = 0; i < first.Length; i++)
        {
            result[i] = (byte)(first[i] ^ second[i]);
        }

        return result;
    }

    public Task<byte[]> EncryptAsync(byte[] data)
    {
        if (data == null)
            throw new ArgumentNullException("Ошибка EncryptAsync: null-data.");

        if (encryptionMode == EncryptionMode.Ecb)
            return Task.Run(() => EncryptECB(data));

        if (encryptionMode == EncryptionMode.Cbc)
            return Task.Run(() => EncryptCBC(data));

        if (encryptionMode == EncryptionMode.Pcbc)
            return Task.Run(() => EncryptPCBC(data));

        if (encryptionMode == EncryptionMode.Cfb)
            return Task.Run(() => EncryptCFB(data));

        if (encryptionMode == EncryptionMode.Ofb)
            return Task.Run(() => EncryptOFB(data));

        if (encryptionMode == EncryptionMode.Ctr)
            return Task.Run(() => EncryptCTR(data));

        if (encryptionMode == EncryptionMode.RandomDelta)
            return Task.Run(() => EncryptRandomDelta(data));

        throw new NotSupportedException("Ошибка EncryptAsync: некорректный режим.");
    }

    private byte[] EncryptECB(byte[] data)
    {
        byte[] paddedData = ApplyPadding(data);
        int blockSize = cipher.BlockSizeBytes;
        byte[] result = new byte[paddedData.Length];
    
        int blockCount = paddedData.Length / blockSize;

        Parallel.For(0, blockCount, blockIndex =>
        {
            int offset = blockIndex * blockSize;

            byte[] block = new byte[blockSize];
            Array.Copy(paddedData, offset, block, 0, blockSize);

            byte[] encryptedBlock = cipher.EncryptBlock(block);

            Array.Copy(encryptedBlock, 0, result, offset, blockSize);
        });

        return result;  
    }

    private byte[] EncryptCBC(byte[] data)
    {
        byte[] paddedData = ApplyPadding(data);
        int blockSize = cipher.BlockSizeBytes;
        byte[] previousBlock = GetIV(blockSize);
        byte[] result = new byte[paddedData.Length];

        for (int offset = 0; offset < paddedData.Length; offset += blockSize)
        {
            byte[] block = new byte[blockSize];
            Array.Copy(paddedData, offset, block, 0, blockSize);

            byte[] mixedBlock = XorBlocks(block, previousBlock);
            byte[] encryptedBlock = cipher.EncryptBlock(mixedBlock);

            Array.Copy(encryptedBlock, 0, result, offset, blockSize);
            previousBlock = encryptedBlock;
        }

        return result;
    }

    private byte[] EncryptPCBC(byte[] data)
    {
        byte[] paddedData = ApplyPadding(data);
        int blockSize = cipher.BlockSizeBytes;
        byte[] result = new byte[paddedData.Length];

        byte[] previousPBlock = GetIV(blockSize);
        byte[] previousCipherBlock = new byte[blockSize];

        for (int offset = 0; offset < paddedData.Length; offset += blockSize)
        {
            byte[] pBlock = new byte[blockSize];
            Array.Copy(paddedData, offset, pBlock, 0, blockSize);

            byte[] mixedBlock = XorBlocks(pBlock, previousPBlock);
            mixedBlock = XorBlocks(mixedBlock, previousCipherBlock);

            byte[] cipherBlock = cipher.EncryptBlock(mixedBlock);
            Array.Copy(cipherBlock, 0, result, offset, blockSize);

            previousPBlock = pBlock;
            previousCipherBlock = cipherBlock;
        }

        return result;
    }

    private byte[] EncryptCFB(byte[] data)
    {
        byte[] paddedData = ApplyPadding(data);
        int blockSize = cipher.BlockSizeBytes;
        byte[] result = new byte[paddedData.Length];

        byte[] prevBlock = GetIV(blockSize);

        for (int offset = 0; offset < paddedData.Length; offset += blockSize)
        {
            byte[] pBlock = new byte[blockSize];
            Array.Copy(paddedData, offset, pBlock, 0, blockSize);

            byte[] tempBlock = cipher.EncryptBlock(prevBlock);
            byte[] cipherBlock = XorBlocks(pBlock, tempBlock);

            Array.Copy(cipherBlock, 0, result, offset, blockSize);

            prevBlock = cipherBlock;
        }

        return result;
    }

    private byte[] EncryptOFB(byte[] data)
    {
        byte[] paddedData = ApplyPadding(data);
        int blockSize = cipher.BlockSizeBytes;
        byte[] result = new byte[paddedData.Length];

        byte[] prevBlock = GetIV(blockSize);

        for (int offset = 0; offset < paddedData.Length; offset += blockSize)
        {
            byte[] pBlock = new byte[blockSize];
            Array.Copy(paddedData, offset, pBlock, 0, blockSize);

            byte[] tempBlock = cipher.EncryptBlock(prevBlock);
            byte[] cipherBlock = XorBlocks(pBlock, tempBlock);

            Array.Copy(cipherBlock, 0, result, offset, blockSize);

            prevBlock = tempBlock;
        }

        return result;
    }

    private static bool TryCount(byte[] counter)
    {
        for (int i = counter.Length - 1; i >= 0; i--)
        {
            if (counter[i] < byte.MaxValue)
            {
                counter[i]++;
                return true;
            }

            counter[i] = 0;
        }

        return false;
    }

    private byte[] ProcessCTR(byte[] data)
    {
        int blockSize = cipher.BlockSizeBytes;
        byte[] result = new byte[data.Length];

        int blockCount = data.Length / blockSize;
        byte[][] counters = new byte[blockCount][];

        byte[] nextCounter =
            (byte[])GetIV(blockSize).Clone();

        for (int i = 0; i < blockCount; i++)
        {
            counters[i] = (byte[])nextCounter.Clone();

            if (i + 1 < blockCount && !TryCount(nextCounter)) throw new InvalidOperationException("Ошибка ProcessCTR: счётчик переполнился.");
        }

        Parallel.For(0, blockCount, blockIndex =>
        {
            int offset = blockIndex * blockSize;

            byte[] inputBlock = new byte[blockSize];
            Array.Copy(data, offset, inputBlock, 0, blockSize);

            byte[] tempBlock = cipher.EncryptBlock(counters[blockIndex]);
            byte[] outputBlock = XorBlocks(inputBlock, tempBlock);

            Array.Copy(outputBlock, 0, result, offset, blockSize);
        });

        return result;
    }

    private byte[] EncryptCTR(byte[] data)
    {
        byte[] paddedData = ApplyPadding(data);
        return ProcessCTR(paddedData);
    }

    private byte[] GetDelta(int blockSize)
    {
        if (additionalParameters == null || additionalParameters.Length == 0 || !(additionalParameters[0] is byte[] delta)) throw new InvalidOperationException("Ошибка GetDelta: первым дополнительным параметром должен быть массив delta.");
        if (delta.Length != blockSize) throw new ArgumentException("Ошибка GetDelta: некорректный размер delta.");
        if ((delta[delta.Length - 1] & 1) == 0) throw new ArgumentException("Ошибка GetDelta: delta должна быть нечётной.");

        return delta;
    }

    private static byte[] AddBlocks(byte[] left, byte[] right)
    {
        if (left.Length != right.Length) throw new ArgumentException("Ошибка AddBlocks: блоки должны иметь одинаковую длину.");

        byte[] result = new byte[left.Length];
        int carry = 0;

        for (int i = left.Length - 1; i >= 0; i--)
        {
            int sum = left[i] + right[i] + carry;

            result[i] = (byte)(sum & 0xFF);
            carry = sum >> 8;
        }

        return result;
    }

    private byte[] ProcessRandomDelta(byte[] data)
    {
        int blockSize = cipher.BlockSizeBytes;
        byte[] delta = GetDelta(blockSize);
        byte[] result = new byte[data.Length];
        int blockCount = data.Length / blockSize;
        byte[][] counters = new byte[blockCount][];

        byte[] nextCounter =
            (byte[])GetIV(blockSize).Clone();

        for (int i = 0; i < blockCount; i++)
        {
            counters[i] = (byte[])nextCounter.Clone();

            if (i + 1 < blockCount)
            {
                nextCounter = AddBlocks(nextCounter, delta);
            }
        }

        Parallel.For(0, blockCount, blockIndex =>
        {
            int offset = blockIndex * blockSize;

            byte[] inputBlock = new byte[blockSize];
            Array.Copy(data, offset, inputBlock, 0, blockSize);

            byte[] tempBlock = cipher.EncryptBlock(counters[blockIndex]);
            byte[] outputBlock = XorBlocks(inputBlock, tempBlock);

            Array.Copy(outputBlock, 0, result, offset, blockSize);
        });

        return result;
    }

    private byte[] EncryptRandomDelta(byte[] data)
    {
        byte[] paddedData = ApplyPadding(data);
        return ProcessRandomDelta(paddedData);
    }

    public Task<byte[]> DecryptAsync(byte[] data)
    {
        if (data == null)
            throw new ArgumentNullException("Ошибка DecryptAsync: null-data.");

        if (encryptionMode == EncryptionMode.Ecb)
            return Task.Run(() => DecryptECB(data));

        if (encryptionMode == EncryptionMode.Cbc)
            return Task.Run(() => DecryptCBC(data));
        
        if (encryptionMode == EncryptionMode.Pcbc)
            return Task.Run(() => DecryptPCBC(data));

        if (encryptionMode == EncryptionMode.Cfb)
            return Task.Run(() => DecryptCFB(data));

        if (encryptionMode == EncryptionMode.Ofb)
            return Task.Run(() => DecryptOFB(data));

        if (encryptionMode == EncryptionMode.Ctr)
            return Task.Run(() => DecryptCTR(data));

        if (encryptionMode == EncryptionMode.RandomDelta)
            return Task.Run(() => DecryptRandomDelta(data));

        throw new NotSupportedException("Ошибка DecryptAsync: некорректный режим.");
    }

    private byte[] DecryptECB(byte[] data)
    {
        int blockSize = cipher.BlockSizeBytes;

        if (data.Length % blockSize != 0) throw new ArgumentException("Ошибка DecryptECB: длина шифротекста должна быть кратна размеру блока.");

        byte[] decryptedData = new byte[data.Length];

        int blockCount = data.Length / blockSize;

        Parallel.For(0, blockCount, blockIndex =>
        {
            int offset = blockIndex * blockSize;

            byte[] block = new byte[blockSize];
            Array.Copy(data, offset, block, 0, blockSize);

            byte[] decryptedBlock = cipher.DecryptBlock(block);

            Array.Copy(decryptedBlock, 0, decryptedData, offset, blockSize);
        });

        return RemovePadding(decryptedData);
    }

    private byte[] DecryptCBC(byte[] data)
    {
        int blockSize = cipher.BlockSizeBytes;

        if (blockSize <= 0) throw new InvalidOperationException("Ошибка DecryptCBC: размер блока должен быть больше нуля.");
        if (data.Length % blockSize != 0) throw new ArgumentException("Ошибка DecryptCBC: длина шифротекста должна быть кратна размеру блока.");

        byte[] previousBlock = GetIV(blockSize);
        byte[] decryptedData = new byte[data.Length];

        int blockCount = data.Length / blockSize;
        byte[] iv = GetIV(blockSize);

        Parallel.For(0, blockCount, blockIndex =>
        {
            int offset = blockIndex * blockSize;

            byte[] cipherBlock = new byte[blockSize];
            Array.Copy(data, offset, cipherBlock, 0, blockSize);

            byte[] decryptedBlock = cipher.DecryptBlock(cipherBlock);

            byte[] previousBlock = new byte[blockSize];

            if (blockIndex == 0)
            {
                Array.Copy(iv, previousBlock, blockSize);
            }
            else
            {
                Array.Copy(data, offset - blockSize, previousBlock, 0, blockSize);
            }

            byte[] pBlock = XorBlocks(decryptedBlock, previousBlock);
            Array.Copy(pBlock, 0, decryptedData, offset, blockSize);
        });

        return RemovePadding(decryptedData);
    }

    private byte[] DecryptPCBC(byte[] data)
    {
        int blockSize = cipher.BlockSizeBytes;

        if (data.Length == 0 || data.Length % blockSize != 0) throw new ArgumentException("Ошибка DecryptPCBC: некорректная длина шифротекста.");

        byte[] decryptedData = new byte[data.Length];

        byte[] previousPBlock = GetIV(blockSize);
        byte[] previousCipherBlock = new byte[blockSize];

        for (int offset = 0; offset < data.Length; offset += blockSize)
        {
            byte[] cipherBlock = new byte[blockSize];
            Array.Copy(data, offset, cipherBlock, 0, blockSize);

            byte[] decryptedBlock = cipher.DecryptBlock(cipherBlock);

            byte[] pBlock = XorBlocks(decryptedBlock, previousPBlock);
            pBlock = XorBlocks(pBlock, previousCipherBlock);

            Array.Copy(pBlock, 0, decryptedData, offset, blockSize);

            previousPBlock = pBlock;
            previousCipherBlock = cipherBlock;
        }

        return RemovePadding(decryptedData);
    }

    private byte[] DecryptCFB(byte[] data)
    {
        int blockSize = cipher.BlockSizeBytes;

        if (data.Length == 0 || data.Length % blockSize != 0) throw new ArgumentException("Ошибка DecryptCFB: некорректная длина шифротекста.");

        byte[] decryptedData = new byte[data.Length];
        byte[] prevBlock = GetIV(blockSize);

        int blockCount = data.Length / blockSize;
        byte[] iv = GetIV(blockSize);

        Parallel.For(0, blockCount, blockIndex =>
        {
            int offset = blockIndex * blockSize;

            byte[] cipherBlock = new byte[blockSize];
            Array.Copy(data, offset, cipherBlock, 0, blockSize);

            byte[] previousBlock = new byte[blockSize];

            if (blockIndex == 0)
            {
                Array.Copy(iv, previousBlock, blockSize);
            }
            else
            {
                Array.Copy(data, offset - blockSize, previousBlock, 0, blockSize);
            }

            byte[] tempBlock = cipher.EncryptBlock(previousBlock);
            byte[] pBlock = XorBlocks(cipherBlock, tempBlock);

            Array.Copy(pBlock, 0, decryptedData, offset, blockSize);
        });

        return RemovePadding(decryptedData);
    }

    private byte[] DecryptOFB(byte[] data)
    {
        int blockSize = cipher.BlockSizeBytes;

        if (data.Length == 0 || data.Length % blockSize != 0) throw new ArgumentException("Ошибка DecryptOFB: некорректная длина шифротекста.");

        byte[] decryptedData = new byte[data.Length];
        byte[] prevBlock = GetIV(blockSize);

        for (int offset = 0; offset < data.Length; offset += blockSize)
        {
            byte[] cipherBlock = new byte[blockSize];
            Array.Copy(data, offset, cipherBlock, 0, blockSize);

            byte[] tempBlock = cipher.EncryptBlock(prevBlock);
            byte[] pBlock = XorBlocks(cipherBlock, tempBlock);

            Array.Copy(pBlock, 0, decryptedData, offset, blockSize);

            prevBlock = tempBlock;
        }

        return RemovePadding(decryptedData);
    }

    private byte[] DecryptCTR(byte[] data)
    {
        int blockSize = cipher.BlockSizeBytes;

        if (data.Length == 0 || data.Length % blockSize != 0) throw new ArgumentException("Ошибка DecryptCTR: некорректная длина шифротекста.");

        byte[] decryptedData = ProcessCTR(data);
        return RemovePadding(decryptedData);
    }

    private byte[] DecryptRandomDelta(byte[] data)
    {
        int blockSize = cipher.BlockSizeBytes;

        if (data.Length == 0 || data.Length % blockSize != 0) throw new ArgumentException("Ошибка DecryptRandomDelta: некорректная длина шифротекста.");

        byte[] decryptedData = ProcessRandomDelta(data);
        return RemovePadding(decryptedData);
    }

    public async Task EncryptFile(string inputPath, string outputPath)
    {
        byte[] data = await File.ReadAllBytesAsync(inputPath);
        byte[] encryptedData = await EncryptAsync(data);
        await File.WriteAllBytesAsync(outputPath, encryptedData);
    }

    public async Task DecryptFile(string inputPath, string outputPath)
    {
        byte[] data = await File.ReadAllBytesAsync(inputPath);
        byte[] decryptedData = await DecryptAsync(data);
        await File.WriteAllBytesAsync(outputPath, decryptedData);
    }
}

// Plan
// V Сохранить шифр, ключ и настройки режима.
// V Добавить дополнение данных.
// V Реализовать режимы по одному.
// V Добавить асинхронные методы для массивов и файлов.
// V Распараллелить обработку там, где режим это позволяет.