using CryptoLab1;

byte[] input = {0b_1011_0010};
int[] pblock = {1,3,8};
byte[] res1 = BitPermutation.Permutate(input, pblock, true, 1); // От старшего
byte[] res2 = BitPermutation.Permutate(input, pblock, false, 1); // От младшего

Console.WriteLine("-^- 1.1 Test (START) -^-");
Console.WriteLine($"Test 1: {BitConverter.ToString(res1)}");
Console.WriteLine($"Test 2: {BitConverter.ToString(res2)}");
Console.WriteLine("-v- 1.1 Test (END) -v-");

await TestCipherContext.RunAsync();