var password = "TestPassword";
var testText = "TestText-TestLine-TestLine-TestLine-TestLine";
Console.WriteLine($"Original Text: : {testText}");

var service = new CryptoService.Implementation.CryptographyService(password);
Console.WriteLine($"Password : {password}");

var encryptedText = service.Encrypt(testText);
Console.WriteLine($"Encrypted Text: {encryptedText}");

var decryptedText = service.Decrypt(encryptedText);
Console.WriteLine($"Decrypted Text: {decryptedText}");

Console.ReadKey();