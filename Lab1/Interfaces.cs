namespace CryptoLab1;

public interface IKeyExpansion
{
    byte[][] GenerateRoundKeys(byte[] masterKey);
}

public interface IRoundFunction
{
    byte[] RoundFunc(byte[] inputBlock, byte[] roundKey);
}

public interface IBlockCipher
{
    int BlockSizeBytes {get; }
    
    void SetKey(byte[] key);
    byte[] EncryptBlock(byte[] block);
    byte[] DecryptBlock(byte[] block);
}