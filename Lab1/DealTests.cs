using System.Security.Cryptography;
using System.Linq;

namespace CryptoLab1;

public static class DealTests
{
    public static async Task RunAsync()
    {
        await RandomBytesTest();
        await FilesTest();
    }

    private static async Task RandomBytesTest()
    {
        byte[] data = new byte[1031];
        RandomNumberGenerator.Fill(data);

        byte[] key =
        {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
        };

        byte[] initializationVector =
        {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE
        };

        byte[] delta =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
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

        foreach (EncryptionMode mode in modes)
        {
            byte[]? iv = mode == EncryptionMode.Ecb ? null : initializationVector;

            CipherContext context;

            if (mode == EncryptionMode.RandomDelta)
            {
                context = new CipherContext(new Deal(), key, mode, PaddingScheme.Pkcs7, iv, delta);
            }
            else
            {
                context = new CipherContext(new Deal(), key, mode, PaddingScheme.Pkcs7, iv);
            }

            byte[] encrypted = await context.EncryptAsync(data);
            byte[] decrypted = await context.DecryptAsync(encrypted);

            bool matches = data.SequenceEqual(decrypted);

            Console.WriteLine($"{mode}: {(matches ? "Успешно!" : "Неудачно((")}");
        }
    }

    private static async Task FilesTest()
    {
        string inputDirectory = Path.Combine(
            Directory.GetCurrentDirectory(), "TestFiles");

        string outputDirectory = Path.Combine(inputDirectory, "Results");
        Directory.CreateDirectory(outputDirectory);

        (string fileName, EncryptionMode mode)[] fileCases =
        {
            ("text.txt", EncryptionMode.Cbc),
            ("music.mp3", EncryptionMode.Cfb),
            ("image.png", EncryptionMode.Ofb),
            ("video.mp4", EncryptionMode.Ctr),
            ("allocator_red_black_tree_tests.cpp", EncryptionMode.Pcbc)
        };

        byte[] key =
        {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
        };

        byte[] initializationVector =
        {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE
        };

        foreach ((string fileName, EncryptionMode mode) in fileCases)
        {
            string inputPath = Path.Combine(inputDirectory, fileName);

            if (!File.Exists(inputPath)) throw new FileNotFoundException("Ошибка FilesTest: файл не найден.", inputPath);

            string encryptedPath = Path.Combine(outputDirectory, fileName + ".deal-encrypted");

            string decryptedPath = Path.Combine(outputDirectory, "deal_" + fileName);

            CipherContext context = new CipherContext(new Deal(), key, mode, PaddingScheme.Pkcs7, initializationVector);

            await context.EncryptFile(inputPath, encryptedPath);
            await context.DecryptFile(encryptedPath, decryptedPath);

            byte[] originalBytes = await File.ReadAllBytesAsync(inputPath);
            byte[] newBytes = await File.ReadAllBytesAsync(decryptedPath);

            bool matches = originalBytes.SequenceEqual(newBytes);

            Console.WriteLine(
                $"{fileName} ({mode}): {(matches ? "Успешно!" : "Неудачно((")}");
        }
    }
}