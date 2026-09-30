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
}

// Plan
// V Сохранить шифр, ключ и настройки режима.
// V Добавить дополнение данных.
// X Реализовать режимы по одному.
// X Добавить асинхронные методы для массивов и файлов.
// X Распараллелить обработку там, где режим это позволяет.