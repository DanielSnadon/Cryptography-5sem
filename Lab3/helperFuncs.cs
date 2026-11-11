using System;

namespace CryptoLab3;

public sealed class HelperFuncs
{
    public byte Add(byte left, byte right)
    {
        return (byte)(left ^ right);
    }
}