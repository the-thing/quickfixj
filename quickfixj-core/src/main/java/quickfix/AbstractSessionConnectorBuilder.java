package quickfix;

import quickfix.mina.SessionConnector;

public abstract class AbstractSessionConnectorBuilder<D extends AbstractSessionConnectorBuilder<D, P>, P extends SessionConnector> {

    private final Class<D> derivedType;
    protected Application application;
    protected MessageStoreFactory messageStoreFactory;
    protected SessionSettings settings;
    protected LogFactory logFactory;
    protected MessageFactory messageFactory;
    protected int queueCapacity = -1;
    protected int queueLowerWatermark = -1;
    protected int queueUpperWatermark = -1;

    protected AbstractSessionConnectorBuilder(Class<D> derivedType) {
        this.derivedType = derivedType;
        this.logFactory = new ScreenLogFactory();
        this.messageFactory = new DefaultMessageFactory();
    }

    public D withApplication(Application val) {
        application = val;
        return derivedType.cast(this);
    }

    public D withMessageStoreFactory(MessageStoreFactory val) {
        messageStoreFactory = val;
        return derivedType.cast(this);
    }

    public D withSettings(SessionSettings val) {
        settings = val;
        return derivedType.cast(this);
    }

    public D withLogFactory(LogFactory val) {
        logFactory = val;
        return derivedType.cast(this);
    }

    public D withMessageFactory(MessageFactory val) {
        messageFactory = val;
        return derivedType.cast(this);
    }

    public D withQueueCapacity(int val) throws ConfigError {
        if (queueLowerWatermark >= 0) {
            throw new ConfigError("queue capacity and watermarks may not be configured together");
        } else if (val < 0) {
            throw new ConfigError("negative queue capacity");
        }
        queueCapacity = val;
        return  derivedType.cast(this);

    }

    public D withQueueWatermarks(int lower, int upper) throws ConfigError {
        if (queueCapacity >= 0) {
            throw new ConfigError("queue capacity and watermarks may not be configured together");
        } else if (lower < 0 || upper <= lower) {
            throw new ConfigError("invalid queue watermarks, required: 0 <= lower watermark < upper watermark");
        }
        queueLowerWatermark = lower;
        queueUpperWatermark = upper;
        return derivedType.cast(this);
    }

    public abstract P build() throws ConfigError;
}
