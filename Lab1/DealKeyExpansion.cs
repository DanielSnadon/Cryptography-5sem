namespace CryptoLab1;

public class DealKeyExpansion : IKeyExpansion
{
    private static readonly byte[] specialDesKey = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    private readonly Des specialDes = new Des();

    public byte[][] GenerateRoundKeys(byte[] masterKey)
    {
        if (masterKey == null) throw new ArgumentNullException("Ошибка GenerateRoundKeys: masterKey не может быть null.");

        if (masterKey.Length != 16 && masterKey.Length != 24 && masterKey.Length != 32) throw new ArgumentException("Ошибка GenerateRoundKeys: некорректный размер ключа DEAL.");

        int keyPartCount = masterKey.Length / 8;
        byte[][] keyParts = new byte[keyPartCount][];

        for (int partIndex = 0; partIndex < keyPartCount; partIndex++)
        {
            keyParts[partIndex] = new byte[8];

            Array.Copy(masterKey, partIndex * 8, keyParts[partIndex], 0, 8);
        }

        int roundCount = keyPartCount == 4 ? 8 : 6;
        byte[][] roundKeys = new byte[roundCount][];

        specialDes.SetKey(specialDesKey);

        for (int roundIndex = 0; roundIndex < roundCount; roundIndex++)
        {
            byte[] inputBlock = (byte[])keyParts[roundIndex % keyPartCount].Clone();

            if (roundIndex > 0)
            {
                for (int byteIndex = 0; byteIndex < 8; byteIndex++)
                {
                    inputBlock[byteIndex] ^= roundKeys[roundIndex - 1][byteIndex];
                }
            }

            if (roundIndex >= keyPartCount)
            {
                int constantShift = roundIndex - keyPartCount;
                inputBlock[7] ^= (byte)(1 << constantShift);
            }

            roundKeys[roundIndex] = specialDes.EncryptBlock(inputBlock);
        }

        return roundKeys;
    }
}