namespace CryptoService.Interfaces
{
    internal interface ICryptographyService
    {
        string Encrypt(string inputText);

        string Decrypt(string inputText);
    }
}
