namespace CryptoLab1;

public interface IKeyExpansion
{
    byte[][] GenerateRoundKeys(byte[] masterKey);
}

public interface IRoundFunction
{
    byte[] Apply(byte[] inputBlock, byte[] roundKey);
}