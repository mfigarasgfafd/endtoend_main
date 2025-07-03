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
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;


public class BenchmarkRunner {
    static {
        // Bouncy Castle provider for 160-bit curve support
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    // ================= DH Key Exchange States =================
    @State(Scope.Benchmark)
    public static class ManualDHKeySizeState {
        @Param({"1024", "3072", "8192"})
        public int keySize;

        ManualDiffieHellman alice;
        ManualDiffieHellman bob;

        @Setup(Level.Trial)
        public void setup() {
            alice = new ManualDiffieHellman();
            alice.setKeySize(keySize);
            alice.initialize();

            bob = new ManualDiffieHellman();
            bob.setKeySize(keySize);
            bob.initialize();
        }
    }

    // ================= ECDH Key Exchange State =================
    @State(Scope.Benchmark)
    public static class ManualECDHKeySizeState {
        @Param({"160", "256", "384"})
        public int keySize;

        ManualECDiffieHellmanBenchmarking alice;
        ManualECDiffieHellmanBenchmarking bob;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            alice = new ManualECDiffieHellmanBenchmarking();
            alice.setKeySize(keySize);
            alice.generateKeyPair();

            bob = new ManualECDiffieHellmanBenchmarking();
            bob.setKeySize(keySize);
            bob.generateKeyPair();
        }
    }

    // ================= Library ECDH Key Exchange State =================
    @State(Scope.Benchmark)
    public static class LibraryECDHKeySizeState {
        private static final Map<Integer, String> curveMap = new HashMap<>();
        static {
            curveMap.put(160, "secp160r1");
            curveMap.put(256, "secp256r1");
            curveMap.put(384, "secp384r1");
        }

        @Param({"160", "256", "384"})
        public int keySize;

        KeyPair aliceKeyPair;
        PublicKey bobPublicKey;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            String curveName = curveMap.get(keySize);
            if (curveName == null) {
                throw new IllegalArgumentException("Unsupported ECDH key size: " + keySize);
            }

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
            kpg.initialize(new ECGenParameterSpec(curveName));
            aliceKeyPair = kpg.generateKeyPair();

            KeyPair bobKeyPair = kpg.generateKeyPair();
            bobPublicKey = bobKeyPair.getPublic();
        }
    }

    // ================= Key Generation States =================
    @State(Scope.Thread)
    public static class DHKeyGenSizeState {
        @Param({"1024", "3072", "8192"})
        public int keySize;
    }

    @State(Scope.Thread)
    public static class ECDHKeyGenSizeState {
        @Param({"160", "256", "384"})
        public int keySize;
    }
    @State(Scope.Benchmark)
    public static class LibraryDHKeySizeState {
        @Param({"1024", "3072", "8192"})
        public int keySize;

        KeyPair aliceKeyPair;
        PublicKey bobPublicKey;
        PrivateKey alicePrivateKey;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(keySize);
            aliceKeyPair = kpg.generateKeyPair();

            KeyPair bobKeyPair = kpg.generateKeyPair();
            bobPublicKey = bobKeyPair.getPublic();
            alicePrivateKey = aliceKeyPair.getPrivate();
        }
    }
//    // ================= DH Benchmarks =================
//    @Benchmark
//    @BenchmarkMode(Mode.AverageTime)
//    @OutputTimeUnit(TimeUnit.MILLISECONDS)
//    @Warmup(iterations = 5, time = 1)
//    @Measurement(iterations = 10, time = 1)
//    @Fork(3)
//    public void manualDhKeyExchange(ManualDHKeySizeState state, Blackhole bh) throws Exception {
//        state.bob.computeSharedSecret(state.alice.getPublicKey());
//        bh.consume(state.bob.getSharedSecret());
//    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Warmup(iterations = 5, time = 1)
    @Measurement(iterations = 10, time = 1)
    @Fork(3)
    public void libraryDhKeyExchange(LibraryDHKeySizeState state, Blackhole bh) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(state.alicePrivateKey);
        ka.doPhase(state.bobPublicKey, true);
        bh.consume(ka.generateSecret());
    }

//    // ================= ECDH Benchmarks =================
//    @Benchmark
//    @BenchmarkMode(Mode.AverageTime)
//    @OutputTimeUnit(TimeUnit.MILLISECONDS)
//    @Warmup(iterations = 5, time = 1)
//    @Measurement(iterations = 10, time = 1)
//    @Fork(3)
//    public void manualEcdhKeyExchange(ManualECDHKeySizeState state, Blackhole bh) throws Exception {
//        state.bob.computeSharedSecret(state.alice.getPublicPoint());
//        bh.consume(state.bob.getSharedSecret());
//    }
//
//    @Benchmark
//    @BenchmarkMode(Mode.AverageTime)
//    @OutputTimeUnit(TimeUnit.MILLISECONDS)
//    @Warmup(iterations = 5, time = 1)
//    @Measurement(iterations = 10, time = 1)
//    @Fork(3)
//    public void libraryEcdhKeyExchange(LibraryECDHKeySizeState state, Blackhole bh) throws Exception {
//        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
//        ka.init(state.aliceKeyPair.getPrivate());
//        ka.doPhase(state.bobPublicKey, true);
//        bh.consume(ka.generateSecret());
//    }
//
//    // ================= Key Generation Benchmarks =================
//    @Benchmark
//    @BenchmarkMode(Mode.AverageTime)
//    @OutputTimeUnit(TimeUnit.MILLISECONDS)
//    @Warmup(iterations = 5, time = 1)
//    @Measurement(iterations = 10, time = 1)
//    @Fork(3)
//    public void manualDhKeyGeneration(DHKeyGenSizeState state, Blackhole bh) {
//        ManualDiffieHellman dh = new ManualDiffieHellman();
//        dh.setKeySize(state.keySize);
//        dh.initialize();
//        bh.consume(dh);
//    }
//
//    @Benchmark
//    @BenchmarkMode(Mode.AverageTime)
//    @OutputTimeUnit(TimeUnit.MILLISECONDS)
//    @Warmup(iterations = 5, time = 1)
//    @Measurement(iterations = 10, time = 1)
//    @Fork(3)
//    public void manualEcdhKeyGeneration(ECDHKeyGenSizeState state, Blackhole bh) throws Exception {
//        ManualECDiffieHellman ecdh = new ManualECDiffieHellman();
//        ecdh.setKeySize(state.keySize);
//        ecdh.generateKeyPair();
//        bh.consume(ecdh);
//    }
//
//    // ================= Library Key Generation Benchmarks =================
//    @Benchmark
//    @BenchmarkMode(Mode.AverageTime)
//    @OutputTimeUnit(TimeUnit.MILLISECONDS)
//    @Warmup(iterations = 5, time = 1)
//    @Measurement(iterations = 10, time = 1)
//    @Fork(3)
//    public void libraryDhKeyGeneration(DHKeyGenSizeState state, Blackhole bh) throws Exception {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
//        kpg.initialize(state.keySize);
//        bh.consume(kpg.generateKeyPair());
//    }
//
//    @Benchmark
//    @BenchmarkMode(Mode.AverageTime)
//    @OutputTimeUnit(TimeUnit.MILLISECONDS)
//    @Warmup(iterations = 5, time = 1)
//    @Measurement(iterations = 10, time = 1)
//    @Fork(3)
//    public void libraryEcdhKeyGeneration(ECDHKeyGenSizeState state, Blackhole bh) throws Exception {
//        String curveName = switch (state.keySize) {
//            case 160 -> "secp160r1";
//            case 256 -> "secp256r1";
//            case 384 -> "secp384r1";
//            default -> throw new IllegalArgumentException("Unsupported ECDH key size");
//        };
//
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
//        kpg.initialize(new ECGenParameterSpec(curveName));
//        bh.consume(kpg.generateKeyPair());
//    }

    public static void main(String[] args) throws RunnerException, IOException {
        String outputFile = "benchmark_results.txt";
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