using System.Security.Cryptography;
using System.Linq;

namespace CryptoLab1;

public static class DesTest
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

        byte[] key = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
        byte[] initializationVector = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
        byte[] delta = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

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
                context = new CipherContext(new Des(), key, mode, PaddingScheme.Pkcs7, iv, delta);
            }
            else
            {
                context = new CipherContext(new Des(), key, mode, PaddingScheme.Pkcs7, iv);
            }

            byte[] encrypted = await context.EncryptAsync(data);
            byte[] decrypted = await context.DecryptAsync(encrypted);

            bool matches = data.SequenceEqual(decrypted);

            Console.WriteLine($"{mode}: {(matches ? "Успешно!" : "Неудачно((")}");
        }
    }

    private static async Task FilesTest()
    {
        string inputDirectory = Path.Combine(Directory.GetCurrentDirectory(), "TestFiles");
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

        byte[] key = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
        byte[] initializationVector = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

        foreach ((string fileName, EncryptionMode mode) in fileCases)
        {
            string inputPath = Path.Combine(inputDirectory, fileName);

            if (!File.Exists(inputPath)) throw new FileNotFoundException("Ошибка FilesTest: файл не найден.");

            string encryptedPath = Path.Combine(outputDirectory, fileName + ".des-encrypted");
            string decryptedPath = Path.Combine(outputDirectory, "des_" + fileName);

            CipherContext context = new CipherContext(new Des(), key, mode, PaddingScheme.Pkcs7, initializationVector);

            await context.EncryptFile(inputPath, encryptedPath);
            await context.DecryptFile(encryptedPath, decryptedPath);

            byte[] originalBytes = await File.ReadAllBytesAsync(inputPath);
            byte[] newBytes = await File.ReadAllBytesAsync(decryptedPath);

            bool matches = originalBytes.SequenceEqual(newBytes);

            Console.WriteLine($"{fileName} ({mode}): {(matches ? "Успешно!" : "Неудачно((")}");
        }
    }
}