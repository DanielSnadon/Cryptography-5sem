using System;

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

    private byte[] ApplyPadding(byte[] data) // PKCS7 for now...
    {
        int blockSize = cipher.BlockSizeBytes;

        int paddingLength = blockSize - data.Length % blockSize;
        byte[] paddedData = new byte[data.Length + paddingLength];

        Array.Copy(data, paddedData, data.Length);

        for (int i = data.Length; i < paddedData.Length; i++)
        {
            paddedData[i] = (byte)paddingLength;
        }

        return paddedData;
    }
}

// Plan
// V Сохранить шифр, ключ и настройки режима.
// X Добавить дополнение данных.
// X Реализовать режимы по одному.
// X Добавить асинхронные методы для массивов и файлов.
// X Распараллелить обработку там, где режим это позволяет.