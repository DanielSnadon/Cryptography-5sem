namespace CryptoLab1;

public enum EncryptionMode
{
    Ecb,
    Cbc,
    Pcbc,
    Cfb,
    Ofb,
    Ctr,
    RandomDelta
}

public enum PaddingScheme
{
    Zeros,
    AnsiX923,
    Pkcs7,
    Iso10126
}