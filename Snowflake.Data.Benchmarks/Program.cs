using BenchmarkDotNet.Running;

namespace Snowflake.Data.Benchmarks
{
    class Program
    {
        static async Task Main(string[] args)
        {
            await Task.Yield();
            BenchmarkRunner.Run<EncryptionStreamBenchmark>();
        }
    }
}
