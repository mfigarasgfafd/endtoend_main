package org.example;

import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

public class BenchmarkRunner {
    public static void main(String[] args) throws Exception {
        Options opt = new OptionsBuilder()
                .include(PerformanceTesting.class.getSimpleName())
                .forks(1)
                .warmupIterations(3)
                .measurementIterations(20)
                .build();

        new Runner(opt).run();
    }
}
