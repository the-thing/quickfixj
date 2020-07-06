package org.quickfixj.benchmark;

public interface InternalProfiler {

    void beforeBenchmark();

    void afterBenchmark();

    void beforeIteration();

    void afterIteration();
}
