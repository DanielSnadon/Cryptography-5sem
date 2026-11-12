using CryptoLab3;
using CryptoLab1;

// _ _ _ Punkt 1 _ _ _
Console.WriteLine("ПУНКТ 1 ПУНКТ 1 ПУНКТ 1 ПУНКТ 1 ПУНКТ 1 ПУНКТ 1 ПУНКТ 1 ПУНКТ 1 ПУНКТ 1 ПУНКТ 1 ПУНКТ 1 ПУНКТ 1 ПУНКТ 1 ПУНКТ 1");

// Обычный функционал:

var service = new HelperFuncs();

Console.WriteLine($"Сложение: 0x{service.Add(0x0B, 0x0D):X2}");
Console.WriteLine($"Умножение: 0x{service.Multiply(0x83, 0x03, 0x1B):X2}");

var moduli = service.GetIreducibles();
Console.WriteLine($"Количество неприводимых модулей: {moduli.Count}");

byte inverse = service.Inverse(0x02, 0x1B);

Console.WriteLine($"Обратный к 0x02: 0x{inverse:X2}");
Console.WriteLine($"Произведение: 0x{service.Multiply(0x02, inverse, 0x1B):X2}");

var factors = service.Factorize(0b11011);
Console.WriteLine($"Множители: {string.Join(", ", factors)}");

// Исключения:

try
{
    service.Inverse(0x00, 0x1B);
    throw new InvalidOperationException("Inverse принимает нулевой элемент.");
}
catch (ArgumentException exception)
{
    Console.WriteLine($"Inverse отклоняет нулевой элемент. {exception}");
}

try
{
    service.Inverse(0x02, 0x01);
    throw new InvalidOperationException("Inverse принимает приводимый модуль.");
}
catch (ArgumentException exception)
{
    Console.WriteLine($"Inverse отклоняет приводимый модуль. {exception}");
}

try
{
    service.Multiply(0x02, 0x03, 0x01);
    throw new InvalidOperationException("Multiply принимает приводимый модуль.");
}
catch (ArgumentException exception)
{
    Console.WriteLine($"Multiply отклоняет приводимый модуль. {exception}");
}

// _ _ _ Punkt 2 _ _ _
Console.WriteLine("ПУНКТ 2 ПУНКТ 2 ПУНКТ 2 ПУНКТ 2 ПУНКТ 2 ПУНКТ 2 ПУНКТ 2 ПУНКТ 2 ПУНКТ 2 ПУНКТ 2 ПУНКТ 2 ПУНКТ 2 ПУНКТ 2 ПУНКТ 2");

int[] sizes = { 128, 192, 256 };
var testRandom = new Random(42);

foreach (int blockBits in sizes)
{
    foreach (int keyBits in sizes)
    {
        var cipher = new Rijndael(blockBits, 0x1B);
        var testKey = new byte[keyBits / 8];
        var testBlock = new byte[blockBits / 8];

        testRandom.NextBytes(testKey);
        testRandom.NextBytes(testBlock);

        cipher.SetKey(testKey);
        byte[] decryptedBlock = cipher.DecryptBlock(cipher.EncryptBlock(testBlock));

        bool passed = decryptedBlock.AsSpan().SequenceEqual(testBlock);
        Console.WriteLine($"Блок {blockBits}, ключ {keyBits}: {(passed ? "OK" : "FAIL")}");
    }
}

// _ _ _ Punkt 3 _ _ _
Console.WriteLine("ПУНКТ 3 ПУНКТ 3 ПУНКТ 3 ПУНКТ 3 ПУНКТ 3 ПУНКТ 3 ПУНКТ 3 ПУНКТ 3 ПУНКТ 3 ПУНКТ 3 ПУНКТ 3 ПУНКТ 3 ПУНКТ 3 ПУНКТ 3");

// НЕ ФАЙЛОВОЕ!!!

var randomBytes = new byte[37];
testRandom.NextBytes(randomBytes);

var byteCases = new List<(string Name, byte[] Data)>
{
    ("Псевдослучайный массив", randomBytes),
    ("Пустой массив", Array.Empty<byte>()),
    ("Нулевой байт", new byte[] { 0x00 })
};

int byteChecksPassed = 0;

foreach (byte testModulus in new byte[] { 0x1B, 0x1D, 0x2B })
foreach (var mode in Enum.GetValues<EncryptionMode>())
foreach (var padding in Enum.GetValues<PaddingScheme>())
foreach (var (name, data) in byteCases)
{
    var cipher = new Rijndael(128, testModulus);
    var key = new byte[16];
    var iv = new byte[cipher.BlockSizeBytes];
    testRandom.NextBytes(key);
    testRandom.NextBytes(iv);

    var delta = new byte[cipher.BlockSizeBytes];
    delta[^1] = 1;

    var context = mode == EncryptionMode.RandomDelta
        ? new CipherContext(cipher, key, mode, padding, iv, delta)
        : new CipherContext(cipher, key, mode, padding, iv);

    byte[] encrypted = await context.EncryptAsync(data);
    byte[] decrypted = await context.DecryptAsync(encrypted);

    if (!decrypted.AsSpan().SequenceEqual(data))
    {
        throw new InvalidOperationException($"FAIL | {name} | {mode} | {padding} | модуль 0x{testModulus:X2}");
    } else {
        Console.WriteLine($"SUCCESS! | {name} | {mode} | {padding} | модуль 0x{testModulus:X2}");
    }

    byteChecksPassed++;
}

Console.WriteLine($"Проверок массивов прошло: {byteChecksPassed}");

// ФАЙЛОВОЕ!!!

string[] inputFiles = Directory.GetFiles("TestFiles");

if (inputFiles.Length == 0)
    throw new InvalidOperationException("Папка TestFiles пуста.");

int[] fileTestSizes = { 128, 192, 256 };
byte[] fileTestModuli = { 0x1B, 0x1D };
string resultsDir = Path.Combine("TestFiles", "Results");
Directory.CreateDirectory(resultsDir);
int caseNumber = 0;

bool testAllFileCombinations = false; // Включить, чтобы всё...

EncryptionMode[] fileModes = testAllFileCombinations ? Enum.GetValues<EncryptionMode>() : new[] { EncryptionMode.Cbc, EncryptionMode.Ctr, EncryptionMode.RandomDelta };

PaddingScheme[] filePaddings = testAllFileCombinations ? Enum.GetValues<PaddingScheme>() : new[] { PaddingScheme.Pkcs7, PaddingScheme.Zeros };

foreach (string inputPath in inputFiles)
{
    byte[] originalHash = await HashFile(inputPath);

    foreach (var mode in fileModes)
    foreach (var padding in filePaddings)
    {
        int blockBits = fileTestSizes[caseNumber % 3];
        int keyBits = fileTestSizes[(caseNumber / 3) % 3];
        byte modulus = fileTestModuli[caseNumber % 2];
        caseNumber++;

        var cipher = new Rijndael(blockBits, modulus);
        var key = new byte[keyBits / 8];
        var iv = new byte[cipher.BlockSizeBytes];
        testRandom.NextBytes(key);
        testRandom.NextBytes(iv);

        var delta = new byte[cipher.BlockSizeBytes];
        delta[^1] = 1;

        var context = mode == EncryptionMode.RandomDelta
            ? new CipherContext(cipher, key, mode, padding, iv, delta)
            : new CipherContext(cipher, key, mode, padding, iv);

        string label = $"{Path.GetFileName(inputPath)} | {mode} | {padding} | " + $"блок {blockBits}, ключ {keyBits}, модуль 0x{modulus:X2}";

        string resultName = $"{Path.GetFileName(inputPath)}__{mode}__{padding}";
        string encryptedPath = Path.Combine(resultsDir, $"{resultName}.enc");
        string originalName = Path.GetFileNameWithoutExtension(inputPath);
        string originalExtension = Path.GetExtension(inputPath);
        string restoredPath = Path.Combine(resultsDir, $"{originalName}__{mode}__{padding}.restored{originalExtension}");
            
        Console.WriteLine($"Шифрую | {label}");

        await context.EncryptFile(inputPath, encryptedPath);
        await context.DecryptFile(encryptedPath, restoredPath);

        byte[] restoredHash = await HashFile(restoredPath);
        if (!originalHash.AsSpan().SequenceEqual(restoredHash))
        {
            throw new InvalidOperationException($"FAIL | {label}");
        }
        Console.WriteLine($"FILE IS GOOD! | {label}");
    }
}

static async Task<byte[]> HashFile(string path)
{
    using var stream = File.OpenRead(path);
    return await System.Security.Cryptography.SHA256.HashDataAsync(stream);
}