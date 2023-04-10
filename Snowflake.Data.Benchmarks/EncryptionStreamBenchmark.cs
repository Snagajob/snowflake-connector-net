using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using Snowflake.Data.Core;
using Snowflake.Data.Core.FileTransfer;

namespace Snowflake.Data.Benchmarks;

/// <summary>
/// Results by # of bytes in rawData buffer
/// 
/// 100,000bytes
/// 
/// |          Method |     Mean |     Error |    StdDev |     Gen0 |     Gen1 |     Gen2 | Allocated |
/// |---------------- |---------:|----------:|----------:|---------:|---------:|---------:|----------:|
/// |   RunFileStream | 10.77 ms | 0.1470 ms | 0.1310 ms |  15.6250 |  15.6250 |  15.6250 | 110.46 KB |
/// | RunMemoryStream | 5.551 ms | 0.0878 ms | 0.0822 ms | 500.0000 | 500.0000 | 500.0000 |   1.72 MB |
/// 
/// 
/// 10,000,000 bytes
/// 
/// |          Method |     Mean |    Error |   StdDev |      Gen0 |      Gen1 |      Gen2 | Allocated |
/// |---------------- |---------:|---------:|---------:|----------:|----------:|----------:|----------:|
/// | RunFileStream   | 46.18 ms | 0.899 ms | 1.503 ms |  333.3333 |  333.3333 |  333.3333 |   9.58 MB |
/// | RunMemoryStream | 39.81 ms | 0.789 ms | 1.025 ms | 1875.0000 | 1875.0000 | 1875.0000 |  92.76 MB |
/// 
/// 220,000,000 bytes
/// 
/// |          Method |      Mean |    Error |    StdDev |   Median |      Gen0 |      Gen1 |      Gen2 | Allocated |
/// |---------------- |----------:|---------:|----------:|---------:|----------:|----------:|----------:|----------:|
/// |   RunFileStream | 1036.0 ms | 69.70 ms | 205.40 ms |          |           |           |           | 209.95 MB |
/// | RunMemoryStream |  935.4 ms | 18.35 ms |  51.46 ms | 918.0 ms | 2000.0000 | 2000.0000 | 2000.0000 |    1.6 GB |
/// 
/// </summary>
[MemoryDiagnoser]
public class EncryptionStreamBenchmark
{
    private static readonly RandomNumberGenerator random;
    private static readonly byte[] rawData;

    static EncryptionStreamBenchmark()
    {
        random = RandomNumberGenerator.Create();
        rawData = new byte[220000000];
        random.GetBytes(rawData);
    }

    [Benchmark]
    public void RunFileStream()
    {
        var randomFileNameCrypt = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        var newFileName = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

        var pgMaterial = new PutGetEncryptionMaterial();
        var metaData = new SFEncryptionMetadata();

        using (var aes = Aes.Create())
        {
            // create a random master key
            var keyBytes = new byte[aes.KeySize / 8];
            random.GetBytes(keyBytes);
            pgMaterial.queryStageMasterKey = Convert.ToBase64String(keyBytes);
        }

        try
        {
            // first, write the data to the crypt file
            using (var encryptStream = EncryptionStream.Create(new MemoryStream(rawData, false), EncryptionStream.CryptMode.Encrypt, pgMaterial, metaData, false))
            using (var dest = File.OpenWrite(randomFileNameCrypt))
            {
                encryptStream.CopyTo(dest);
            }

            // next read the data from the encrypted file into the newStream
            using (var dest = File.OpenWrite(newFileName))
            using (var decryptStream = EncryptionStream.Create(File.OpenRead(randomFileNameCrypt), EncryptionStream.CryptMode.Decrypt, pgMaterial, metaData, false))
            {
                decryptStream.CopyTo(dest);
            }

            var newBytes = File.ReadAllBytes(newFileName);
        }
        finally
        {
            // cleanup the temporary file
            File.Delete(randomFileNameCrypt);
            File.Delete(newFileName);
        }
    }
    
    [Benchmark]
    public void RunMemoryStream()
    {
        var randomFileNameCrypt = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

        var pgMaterial = new PutGetEncryptionMaterial();
        var metaData = new SFEncryptionMetadata();

        using (var aes = Aes.Create())
        {
            // create a random master key
            var keyBytes = new byte[aes.KeySize / 8];
            random.GetBytes(keyBytes);
            pgMaterial.queryStageMasterKey = Convert.ToBase64String(keyBytes);
        }

        string newFileName = null;
        try
        {
            // first, write the data to the crypt file
            var encryptedBytes = EncryptionProvider.EncryptStream(new MemoryStream(rawData, false), pgMaterial, metaData);
            using (var dest = File.OpenWrite(randomFileNameCrypt))
            {
                using (var encryptStream = new MemoryStream(encryptedBytes, false))
                {
                    encryptStream.CopyTo(dest);
                }
            }

            // next decrypt the file into a new file
            newFileName = EncryptionProvider.DecryptFile(randomFileNameCrypt, pgMaterial, metaData);

            var plainBytes = File.ReadAllBytes(newFileName);
        }
        finally
        {
            // cleanup the temporary file
            File.Delete(randomFileNameCrypt);
            if (newFileName != null)
            {
                File.Delete(newFileName);
            }
        }
    }
}