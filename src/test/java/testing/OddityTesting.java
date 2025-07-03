package testing;
import org.example.ManualDiffieHellman;
import org.example.ManualECDiffieHellmanBenchmarking;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.VerboseMode;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import javax.crypto.KeyAgreement;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.TimeUnit;



public class OddityTesting {

    @State(Scope.Benchmark)
    public static class ECDHKeySizeState {
        @Param({"160", "256"})
        public int keySize;

        ManualECDiffieHellmanBenchmarking manualAlice;
        ManualECDiffieHellmanBenchmarking manualBob;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            manualAlice = new ManualECDiffieHellmanBenchmarking();
            manualAlice.setKeySize(keySize);
            manualAlice.generateKeyPair();

            manualBob = new ManualECDiffieHellmanBenchmarking();
            manualBob.setKeySize(keySize);
            manualBob.generateKeyPair();
        }
    }


    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Warmup(iterations = 5, time = 1)
    @Measurement(iterations = 10, time = 1)
    @Fork(3)
    public void libraryEcdhKeyExchange(Blackhole bh) throws Exception {
        // Fixed curve for comparison
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair alice = kpg.generateKeyPair();
        KeyPair bob = kpg.generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(alice.getPrivate());
        ka.doPhase(bob.getPublic(), true);
        bh.consume(ka.generateSecret());
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Warmup(iterations = 5, time = 1)
    @Measurement(iterations = 10, time = 1)
    @Fork(3)
    public void libraryEcdhKeyGeneration(BenchmarkRunner.ECDHKeyGenSizeState state, Blackhole bh) throws Exception {
        String curveName = switch (state.keySize) {
            case 160 -> "secp160r1";
            case 256 -> "secp256r1";
            default -> throw new InvalidParameterException("Unsupported key size");
        };

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(curveName));
        bh.consume(kpg.generateKeyPair());
    }

    public static void main(String[] args) throws RunnerException, IOException {
        String outputFile = "oddity_results_160.txt";
        PrintWriter writer = new PrintWriter(new FileWriter(outputFile));

        Options opt = new OptionsBuilder()
                .include(BenchmarkRunner.class.getSimpleName())
                .verbosity(VerboseMode.NORMAL)
                .shouldDoGC(true)
                .resultFormat(ResultFormatType.TEXT)
                .output(outputFile)
                .build();

        writer.println("Benchmark started at: " + new java.util.Date());
        writer.flush();

        new Runner(opt).run();

        writer.println("\nBenchmark completed at: " + new java.util.Date());
        writer.close();
        System.out.println("Results saved to: " + outputFile);
    }


}
