using CryptoLab1;

Console.WriteLine("-^- 1.1 Test (START) -^-");

byte[] input = {0b_1011_0010};
int[] pblock = {1,3,8};
byte[] res1 = BitPermutation.Permutate(input, pblock, true, 1);
byte[] res2 = BitPermutation.Permutate(input, pblock, false, 1);

// input: 0xB2 = 10110010
// res1:  0x33 = 00110011
// res2:  0x36 = 00110110

Console.WriteLine($"Test 1: {BitConverter.ToString(res1)}");
Console.WriteLine($"Test 2: {BitConverter.ToString(res2)}");

Console.WriteLine("-v- 1.1 Test (END) -v-");



Console.WriteLine("-^- 1.2 Test (START) -^-");

await TestCipherContext.RunAsync();

Console.WriteLine("-v- 1.2 Test (END) -v-");



Console.WriteLine("-^- 1.4 Test (START) -^-");

byte[] key =
{
    0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1
};

IKeyExpansion keyExpansion = new DesKeyExpansion();

byte[] rightHalf = { 0xF0, 0xAA, 0xF0, 0xAA };
byte[] roundKey = { 0x1B, 0x02, 0xEF, 0xFC, 0x70, 0x72 };
byte[] expected = { 0x23, 0x4A, 0xA9, 0xBB };

IRoundFunction roundFunction = new DesRoundFunction();
byte[] actual = roundFunction.RoundFunc(rightHalf, roundKey);

Console.WriteLine($"Ожидается: {BitConverter.ToString(expected)}");
Console.WriteLine($"Получено:  {BitConverter.ToString(actual)}");

Console.WriteLine("-v- 1.4 Test (END) -v-");



Console.WriteLine("-^- 1.5 Test (START) -^-");

await DesTest.RunAsync();

Console.WriteLine("-v- 1.5 Test (END) -v-");



Console.WriteLine("-^- 1.6 Test (START) -^-");

byte[] key2 =
{
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};

byte[] originalBlock =
{
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

Deal deal = new Deal();
deal.SetKey(key2);

byte[] encryptedBlock = deal.EncryptBlock(originalBlock);
byte[] decryptedBlock = deal.DecryptBlock(encryptedBlock);

Console.WriteLine($"Исходный блок:      {Convert.ToHexString(originalBlock)}");
Console.WriteLine($"Зашифрованный блок: {Convert.ToHexString(encryptedBlock)}");
Console.WriteLine($"Расшифрованный блок: {Convert.ToHexString(decryptedBlock)}");

Console.WriteLine("-v- 1.6 Test (END) -v-");



Console.WriteLine("-^- 1.7 Test (START) -^-");

await DealTests.RunAsync();

Console.WriteLine("-v- 1.7 Test (END) -v-");

