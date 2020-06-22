/*******************************************************************************
 * Copyright (c) quickfixengine.org  All rights reserved.
 *
 * This file is part of the QuickFIX FIX Engine
 *
 * This file may be distributed under the terms of the quickfixengine.org
 * license as defined by quickfixengine.org and appearing in the file
 * LICENSE included in the packaging of this file.
 *
 * This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING
 * THE WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * See http://www.quickfixengine.org/LICENSE for licensing information.
 *
 * Contact ask@quickfixengine.org if any conditions of this licensing
 * are not clear to you.
 ******************************************************************************/

package org.quickfixj.benchmark.options;

public class BenchmarkOptions {

    private static final BenchmarkProtocol DEFAULT_PROTOCOL = BenchmarkProtocol.SOCKET;
    private static final int DEFAULT_QUEUE_CAPACITY = 4096;
    private static final int DEFAULT_LOWER_WATERMARK = -1;
    private static final int DEFAULT_UPPER_WATERMARK = -1;
    private static final int DEFAULT_MESSAGE_COUNT = 150_000;

    private static final String MESSAGE_COUNT_PROPERTY = "benchmark.message.count";
    private static final String QUEUE_CAPACITY_PROPERTY = "benchmark.queue.capacity";
    // TODO add more

    private BenchmarkProtocol protocol;
    private int queueCapacity;
    private int queueLowerWatermark;
    private int queueUpperWatermark;
    private int messageCount;

    public BenchmarkOptions() {
        this.protocol = BenchmarkProtocol.SOCKET;
        this.queueCapacity = DEFAULT_QUEUE_CAPACITY;
        this.queueLowerWatermark = DEFAULT_LOWER_WATERMARK;
        this.queueUpperWatermark = DEFAULT_UPPER_WATERMARK;
        this.messageCount = DEFAULT_MESSAGE_COUNT;
    }

    public BenchmarkProtocol getProtocol() {
        return protocol;
    }

    public void setProtocol(BenchmarkProtocol protocol) {
        this.protocol = protocol;
    }

    public int getQueueCapacity() {
        return queueCapacity;
    }

    public void setQueueCapacity(int queueCapacity) {
        this.queueCapacity = queueCapacity;
    }

    public int getQueueLowerWatermark() {
        return queueLowerWatermark;
    }

    public void setQueueLowerWatermark(int queueLowerWatermark) {
        this.queueLowerWatermark = queueLowerWatermark;
    }

    public int getQueueUpperWatermark() {
        return queueUpperWatermark;
    }

    public void setQueueUpperWatermark(int queueUpperWatermark) {
        this.queueUpperWatermark = queueUpperWatermark;
    }
}
