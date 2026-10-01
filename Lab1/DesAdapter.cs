namespace CryptoLab1;

public class DesRoundFunctionAdapter : IRoundFunction
{
    private readonly Des des = new Des();

    public byte[] RoundFunc(byte[] inputBlock, byte[] roundKey)
    {
        if (inputBlock == null) throw new ArgumentNullException("Ошибка адаптера: входной блок не может быть null.");
        if (roundKey == null) throw new ArgumentNullException("Ошибка адаптера: раундовый ключ не может быть null.");
        if (inputBlock.Length != 8) throw new ArgumentException("Ошибка адаптера: вход раундовой функции DEAL должен занимать 8 байт.");
        if (roundKey.Length != 8) throw new ArgumentException("Ошибка адаптера: раундовый ключ DEAL должен занимать 8 байт.");

        des.SetKey(roundKey);
        return des.EncryptBlock(inputBlock);
    }
}