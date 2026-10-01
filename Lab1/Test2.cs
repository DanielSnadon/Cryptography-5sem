using System;
using System.Linq;
using System.Threading.Tasks;

namespace CryptoLab1;

public static class TestCipherContext
{
    public static async Task RunAsync()
    {
        byte[] key = { 0x10, 0x20, 0x30, 0x40 };
        byte[] initializationVector = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        byte[] delta = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

        byte[][] testData =
        {
            new byte[] { 0x11, 0x22, 0x33 },
            new byte[] { 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87 },
            new byte[] { 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9A, 0xAB, 0xBC, 0xCD }
        };

        EncryptionMode[] modes =
        {
            EncryptionMode.Ecb,
            EncryptionMode.Cbc,
            EncryptionMode.Pcbc,
            EncryptionMode.Cfb,
            EncryptionMode.Ofb,
            EncryptionMode.Ctr,
            EncryptionMode.RandomDelta
        };

        PaddingScheme[] paddingSchemes =
        {
            PaddingScheme.Zeros,
            PaddingScheme.AnsiX923,
            PaddingScheme.Pkcs7,
            PaddingScheme.Iso10126
        };

        int testNumber = 1;
        
        Console.WriteLine("-^- 1.2 Test (START) -^-");

        foreach (EncryptionMode mode in modes)
        {
            foreach (PaddingScheme paddingScheme in paddingSchemes)
            {
                foreach (byte[] originalData in testData)
                {
                    IBlockCipher testCipher = new TestBlockCipher();

                    CipherContext context = mode == EncryptionMode.RandomDelta
                        ? new CipherContext(testCipher, key, mode, paddingScheme, initializationVector, delta)
                        : new CipherContext(testCipher, key, mode, paddingScheme, initializationVector);

                    byte[] encryptedData = await context.EncryptAsync(originalData);
                    byte[] decryptedData = await context.DecryptAsync(encryptedData);

                    bool passed = originalData.SequenceEqual(decryptedData);

                    Console.WriteLine($"Тест {testNumber}: {mode}, {paddingScheme}, {originalData.Length} bytes - " + (passed ? "YES!" : "NO..."));

                    if (!passed)
                    {
                        Console.WriteLine($"Original:  {BitConverter.ToString(originalData)}");
                        Console.WriteLine($"Decrypted: {BitConverter.ToString(decryptedData)}");

                        throw new InvalidOperationException($"Тест failed: mode={mode}, padding={paddingScheme}.");
                    }

                    testNumber++;
                }
            }
        }

        Console.WriteLine($"Все {testNumber - 1} теста пройдены.");

        Console.WriteLine("-v- 1.2 Test (END) -v-");
    }

    private sealed class TestBlockCipher : IBlockCipher
    {
        private const int TestBlockSizeBytes = 8;
        private byte[] key = Array.Empty<byte>();

        public int BlockSizeBytes => TestBlockSizeBytes;

        public void SetKey(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length == 0)
                throw new ArgumentException("Ошибка SetKey: ключ не может быть пустым.", nameof(key));

            this.key = (byte[])key.Clone();
        }

        public byte[] EncryptBlock(byte[] block)
        {
            return TransformBlock(block);
        }

        public byte[] DecryptBlock(byte[] block)
        {
            return TransformBlock(block);
        }

        private byte[] TransformBlock(byte[] block) // Временная замена DES/DEAL
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (block.Length != TestBlockSizeBytes)
                throw new ArgumentException("Ошибка TransformBlock: блок должен содержать ровно 8 байт.", nameof(block));

            if (key.Length == 0)
                throw new InvalidOperationException("Ошибка TransformBlock: SetKey must be called before block processing.");

            byte[] result = new byte[TestBlockSizeBytes];

            for (int i = 0; i < TestBlockSizeBytes; i++)
            {
                byte positionMask = (byte)(0x5A + i * 17);
                result[i] = (byte)(block[i] ^ key[i % key.Length] ^ positionMask);
            }

            return result;
        }
    }
}
