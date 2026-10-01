namespace CryptoLab1;

public class Deal : IBlockCipher
{
    private readonly FeistelNetwork feistelNetwork;

    public int BlockSizeBytes => 16;

    public Deal()
    {
        feistelNetwork = new FeistelNetwork(new DealKeyExpansion(), new DesRoundFunctionAdapter(), BlockSizeBytes);
    }

    public void SetKey(byte[] key)
    {
        feistelNetwork.SetKey(key);
    }

    public byte[] EncryptBlock(byte[] block)
    {
        return feistelNetwork.EncryptBlock(block);
    }

    public byte[] DecryptBlock(byte[] block)
    {
        return feistelNetwork.DecryptBlock(block);
    }
}