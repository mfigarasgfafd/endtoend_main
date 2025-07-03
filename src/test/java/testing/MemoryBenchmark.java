package testing;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.example.ManualDiffieHellman;
import org.example.ManualECDiffieHellmanBenchmarking;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import javax.crypto.KeyAgreement;
import java.io.*;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.concurrent.TimeUnit;

public class MemoryBenchmark {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // ─────── KEY-SIZE MEASUREMENTS ─────────────────────────────

    public static void printKeySizeMeasurements() throws Exception {
        System.out.println("=== Key Size Measurements ===");

        // --- Manual DH (1024, 2048, 3072, 8192) ---
        for (int ks : new int[]{1024, 2048, 3072, 8192}) {
            ManualDiffieHellman dh = new ManualDiffieHellman();
            dh.setKeySize(ks);
            dh.initialize();

            byte[] priv = dh.getPrivateKey().toByteArray();
            byte[] pub  = dh.getPublicKey().toByteArray();
            dh.computeSharedSecret(dh.getPublicKey());
            byte[] ss   = dh.getSharedSecret();

            System.out.printf("Manual DH-%d  | Private Key: %4d B | Public Key: %4d B | Shared Secret: %3d B%n",
                    ks, priv.length, pub.length, ss.length);
        }
        System.out.println();

        // --- Library DH (1024, 2048, 3072, 8192) ---
        for (int ks : new int[]{1024, 2048, 3072, 8192}) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(ks);
            KeyPair kp = kpg.generateKeyPair();

            byte[] priv = kp.getPrivate().getEncoded();
            byte[] pub  = kp.getPublic().getEncoded();
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(kp.getPrivate());
            ka.doPhase(kp.getPublic(), true);
            byte[] ss = ka.generateSecret();

            System.out.printf("Library DH-%d | Private Key: %4d B | Public Key: %4d B | Shared Secret: %3d B%n",
                    ks, priv.length, pub.length, ss.length);
        }
        System.out.println();

        // --- Manual ECDH (160, 256, 384) ---
        for (int ks : new int[]{160, 256, 384}) {
            ManualECDiffieHellmanBenchmarking ecdh = new ManualECDiffieHellmanBenchmarking();
            ecdh.setKeySize(ks);
            ecdh.generateKeyPair();

            byte[] priv = ecdh.getPrivateKeyBytes();
            byte[] pub  = ecdh.getPublicKeyBytes();
            ecdh.computeSharedSecret(ecdh.getPublicPoint());
            byte[] ss   = ecdh.getSharedSecret();

            System.out.printf("Manual ECDH-P%d | Private Key: %3d B | Public Key: %3d B | Shared Secret: %3d B%n",
                    ks, priv.length, pub.length, ss.length);
        }
        System.out.println();

        // --- Library ECDH (160, 256, 384) ---
        Map<Integer,String> curveMap = Map.of(
                160, "secp160r1",
                256, "secp256r1",
                384, "secp384r1"
        );
        for (int ks : new int[]{160, 256, 384}) {
            String curve = curveMap.get(ks);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
            kpg.initialize(new ECGenParameterSpec(curve));
            KeyPair kp = kpg.generateKeyPair();

            byte[] priv = kp.getPrivate().getEncoded();
            byte[] pub  = kp.getPublic().getEncoded();
            KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
            ka.init(kp.getPrivate());
            ka.doPhase(kp.getPublic(), true);
            byte[] ss = ka.generateSecret();

            System.out.printf("Library ECDH-P%d | Private Key: %3d B | Public Key: %3d B | Shared Secret: %3d B%n",
                    ks, priv.length, pub.length, ss.length);
        }
        System.out.println();
    }



    // ─────── JMH STATES ────────────────────────────────────────
    @State(Scope.Benchmark)
    public static class ManualDHKeySizeState {
        @Param({"1024", "3072", "8192"}) public int keySize;
        ManualDiffieHellman alice, bob;
        @Setup(Level.Trial)
        public void setup() {
            alice = new ManualDiffieHellman();
            alice.setKeySize(keySize); alice.initialize();
            bob   = new ManualDiffieHellman();
            bob.setKeySize(keySize);   bob.initialize();
        }
    }

    @State(Scope.Benchmark)
    public static class ManualECDHKeySizeState {
        @Param({"160", "256", "384"}) public int keySize;
        ManualECDiffieHellmanBenchmarking alice, bob;
        @Setup(Level.Trial)
        public void setup() throws Exception {
            alice = new ManualECDiffieHellmanBenchmarking();
            alice.setKeySize(keySize); alice.generateKeyPair();
            bob   = new ManualECDiffieHellmanBenchmarking();
            bob.setKeySize(keySize);   bob.generateKeyPair();
        }
    }

    @State(Scope.Benchmark)
    public static class LibraryECDHKeySizeState {
        private static final Map<Integer, String> curveMap = Map.of(
                160, "secp160r1", 256, "secp256r1", 384, "secp384r1"
        );
        @Param({"160", "256", "384"}) public int keySize;
        KeyPair alicePair; PublicKey bobPub;
        @Setup(Level.Trial)
        public void setup() throws Exception {
            String curve = curveMap.get(keySize);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
            kpg.initialize(new ECGenParameterSpec(curve));
            alicePair = kpg.generateKeyPair();
            bobPub     = kpg.generateKeyPair().getPublic();
        }
    }

    @State(Scope.Thread)
    public static class DHKeyGenSizeState {
        @Param({"1024", "3072", "8192"}) public int keySize;
    }

    @State(Scope.Thread)
    public static class ECDHKeyGenSizeState {
        @Param({"160", "256", "384"}) public int keySize;
    }

    @State(Scope.Benchmark)
    public static class LibraryDHKeySizeState {
        @Param({"1024", "3072", "8192"})
        public int keySize;

        KeyPair alicePair;
        PublicKey bobPub;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(keySize);
            alicePair = kpg.generateKeyPair();
            bobPub     = kpg.generateKeyPair().getPublic();
        }
    }

//     ─────── BENCHMARKS ────────────────────────────────────────
    @Benchmark @BenchmarkMode(Mode.AverageTime) @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void manualDhExchange(ManualDHKeySizeState s, Blackhole bh) throws InvalidKeyException {
        s.bob.computeSharedSecret(s.alice.getPublicKey());
        bh.consume(s.bob.getSharedSecret());
    }
    @Benchmark @BenchmarkMode(Mode.AverageTime) @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void manualDhKeyGen(DHKeyGenSizeState s, Blackhole bh) {
        ManualDiffieHellman dh = new ManualDiffieHellman();
        dh.setKeySize(s.keySize); dh.initialize();
        bh.consume(dh);
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void libraryDhExchange(LibraryDHKeySizeState s, Blackhole bh) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(s.alicePair.getPrivate());
        ka.doPhase(s.bobPub, true);
        bh.consume(ka.generateSecret());
    }
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void libraryDhKeyGeneration(DHKeyGenSizeState s, Blackhole bh) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(s.keySize);
        bh.consume(kpg.generateKeyPair());
    }


    @Benchmark @BenchmarkMode(Mode.AverageTime) @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void manualEcdhExchange(ManualECDHKeySizeState s, Blackhole bh) throws Exception {
        s.bob.computeSharedSecret(s.alice.getPublicPoint());
        bh.consume(s.bob.getSharedSecret());
    }

    @Benchmark @BenchmarkMode(Mode.AverageTime) @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void manualEcdhKeyGen(ECDHKeyGenSizeState s, Blackhole bh) throws Exception {
        ManualECDiffieHellmanBenchmarking ecdh = new ManualECDiffieHellmanBenchmarking();
        ecdh.setKeySize(s.keySize); ecdh.generateKeyPair();
        bh.consume(ecdh);
    }

    @Benchmark @BenchmarkMode(Mode.AverageTime) @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void libraryEcdhExchange(LibraryECDHKeySizeState s, Blackhole bh) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(s.alicePair.getPrivate());
        ka.doPhase(s.bobPub, true);
        bh.consume(ka.generateSecret());
    }

    @Benchmark @BenchmarkMode(Mode.AverageTime) @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void libraryEcdhKeyGen(ECDHKeyGenSizeState s, Blackhole bh) throws Exception {
        String curve = switch (s.keySize) {
            case 160 -> "secp160r1";
            case 256 -> "secp256r1";
            default  -> "secp384r1";
        };
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new ECGenParameterSpec(curve));
        bh.consume(kpg.generateKeyPair());
    }

    // ─────── RUNNER & POST-PROCESS ────────────────────────────
    public static void main(String[] args) throws Exception {
        // 1) Print actual key‐size bytes
        printKeySizeMeasurements();

        // 2) Run JMH with GCProfiler only
        Options opts = new OptionsBuilder()
                .include(MemoryBenchmark.class.getSimpleName())
                .shouldDoGC(true)
                .addProfiler(GCProfiler.class)
                .resultFormat(org.openjdk.jmh.results.format.ResultFormatType.TEXT)
                .output("memory_benchmark_results_maybefixed.txt")
                .forks(1)
                .build();

        new Runner(opts).run();

        // 3) Read & filter the output for only gc.alloc.rate.norm (B/op)
        List<String> all =
                new BufferedReader(new FileReader("memory_benchmark_results_maybefixed.txt"))
                        .lines().collect(Collectors.toList());

        Pattern p = Pattern.compile(
                "^(MemoryBenchmark\\.(\\S+))\\s+" +  // full method
                        "(\\d+)\\s+\\S+\\s+(\\d+)\\s+" +      // keySize, cnt
                        "([\\d.]+)\\s+±\\s+([\\d.]+)\\s+" +   // mean ± err
                        "B/op$"                               // units
        );

        // collect by implementation → operation → keySize
        Map<String,Map<String,Map<Integer,Stats>>> data = new LinkedHashMap<>();
        for(String line : all) {
            Matcher m = p.matcher(line);
            if (!m.find()) continue;
            String full = m.group(1);
            int keySize = Integer.parseInt(m.group(3));
            int cnt     = Integer.parseInt(m.group(4));
            double mean = Double.parseDouble(m.group(5));
            double err  = Double.parseDouble(m.group(6));
            double stdPct = (mean==0? 0 : (err/mean*100));

            // decide buckets:
            String impl, op;
            if (full.contains("manualEcdh"))      { impl="Manual ECDH"; op="Key Exchange"; }
            else if (full.contains("manualEcdhKeyGen")) { impl="Manual ECDH"; op="Key Generation"; }
            else if (full.contains("libraryEcdhExchange")) { impl="Library ECDH"; op="Key Exchange"; }
            else if (full.contains("libraryEcdhKeyGen"))    { impl="Library ECDH"; op="Key Generation"; }
            else if (full.contains("manualDhExchange"))     { impl="Manual DH"; op="Key Exchange"; }
            else if (full.contains("manualDhKeyGen"))       { impl="Manual DH"; op="Key Generation"; }
            else if (full.contains("libraryDhKeyGen"))      { impl="Library DH"; op="Key Generation"; }
            else if (full.contains("libraryDhKeyExchange"))      { impl="Library DH"; op="Key Exchange"; }


            else continue;

            data.computeIfAbsent(impl, k->new LinkedHashMap<>())
                    .computeIfAbsent(op, k->new LinkedHashMap<>())
                    .put(keySize, new Stats(mean, stdPct, cnt));
        }

        // 4) Print the four tables
        for (String impl : data.keySet()) {
            System.out.println("\n=== " + impl + " ===");
            // header row
            Map<Integer,Stats> anyOp = data.get(impl).values().iterator().next();
            List<Integer> sizes = new ArrayList<>(anyOp.keySet());
            Collections.sort(sizes);
            System.out.print("Operation       ");
            for (int sz : sizes) System.out.printf(" | %4d", sz);
            System.out.println();

            // each op
            for (String op : data.get(impl).keySet()) {
                System.out.printf("%-15s", op);
                Map<Integer,Stats> row = data.get(impl).get(op);
                for (int sz : sizes) {
                    Stats st = row.get(sz);
                    System.out.printf(" | %5.1f±%4.1f%%(%d)", st.mean, st.stdPct, st.count);
                }
                System.out.println();
            }
        }
    }

    // helper to store stats
    static class Stats {
        final double mean, stdPct;
        final int count;
        Stats(double mean, double stdPct, int count) {
            this.mean   = mean;
            this.stdPct = stdPct;
            this.count  = count;
        }
    }
}
