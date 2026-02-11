package quickfix.mina;

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoop;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.ServerSocketChannel;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.handler.codec.base64.Base64;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.ssl.SslContext;
import io.netty.util.CharsetUtil;
import io.netty.util.NetUtil;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.DefaultThreadFactory;
import io.netty.util.internal.PlatformDependent;
import io.netty.util.internal.SocketUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Queue;
import java.util.concurrent.LinkedBlockingDeque;

/**
 * Http proxy server implementation with basic authentication support. The implementation is an adapted copy of Netty's
 * HttpProxyServer samples.
 *
 * <pre>
 * io.netty.handler.proxy.ProxyServer
 * io.netty.handler.proxy.HttpProxyServer
 * </pre>
 */
public class HttpProxyServer {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpProxyServer.class);

    private final ServerSocketChannel ch;
    private final Deque<Throwable> recordedExceptions = new LinkedBlockingDeque<>();
    private final TestMode testMode;
    private final String username;
    private final String password;
    private final InetSocketAddress destination;

    HttpProxyServer(TestMode testMode, int port, InetSocketAddress destination) {
        this(null, testMode, port, destination, null, null);
    }

    HttpProxyServer(SslContext sslContext, TestMode testMode, int port, InetSocketAddress destination, String username, String password) {
        this.testMode = testMode;
        this.destination = destination;
        this.username = username;
        this.password = password;

        ServerBootstrap b = new ServerBootstrap();
        b.channel(NioServerSocketChannel.class);
        b.group(new MultiThreadIoEventLoopGroup(3, new DefaultThreadFactory("proxy", true), NioIoHandler.newFactory()));
        b.childHandler(new ChannelInitializer<SocketChannel>() {
            @Override
            protected void initChannel(SocketChannel ch) {
                ChannelPipeline p = ch.pipeline();

                if (sslContext != null) {
                    p.addLast(sslContext.newHandler(ch.alloc()));
                }

                configure(ch);
            }
        });

        ch = (ServerSocketChannel) b.bind(NetUtil.LOCALHOST, port).syncUninterruptibly().channel();
    }

    protected void configure(SocketChannel ch) {
        ChannelPipeline p = ch.pipeline();
        switch (testMode) {
            case INTERMEDIARY:
                p.addLast(new HttpServerCodec());
                p.addLast(new HttpObjectAggregator(1));
                p.addLast(new HttpIntermediaryHandler());
                break;
            case TERMINAL:
                p.addLast(new HttpServerCodec());
                p.addLast(new HttpObjectAggregator(1));
                p.addLast(new HttpTerminalHandler());
                break;
            case UNRESPONSIVE:
                p.addLast(new UnresponsiveHandler());
                break;
        }
    }

    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    private boolean authenticate(ChannelHandlerContext ctx, FullHttpRequest req) {
        if (!req.method().equals(HttpMethod.CONNECT)) {
            throw new IllegalArgumentException("Only HTTP CONNECT method is supported");
        }

        if (testMode != TestMode.INTERMEDIARY) {
            ctx.pipeline().addBefore(ctx.name(), "lineDecoder", new LineBasedFrameDecoder(64, false, true));
        }

        ctx.pipeline().remove(HttpObjectAggregator.class);
        ctx.pipeline().get(HttpServerCodec.class).removeInboundHandler();

        boolean authzSuccess = false;
        if (username != null) {
            CharSequence authz = req.headers().get(HttpHeaderNames.PROXY_AUTHORIZATION);
            if (authz != null) {
                String[] authzParts = authz.toString().split(" ", 2);
                ByteBuf authzBuf64 = Unpooled.copiedBuffer(authzParts[1], CharsetUtil.US_ASCII);
                ByteBuf authzBuf = Base64.decode(authzBuf64);

                String expectedAuthz = username + ':' + password;
                authzSuccess = "Basic".equals(authzParts[0]) &&
                        expectedAuthz.equals(authzBuf.toString(CharsetUtil.US_ASCII));

                authzBuf64.release();
                authzBuf.release();
            }
        } else {
            authzSuccess = true;
        }

        return authzSuccess;
    }

    private void recordException(Throwable t) {
        LOGGER.warn("Unexpected exception from proxy server", t);
        recordedExceptions.add(t);
    }

    public final void checkExceptions() {
        Throwable last = recordedExceptions.pollLast();

        if (last != null) {
            PlatformDependent.throwException(last);
        }
    }

    public void stop() {
        ch.close();
    }

    protected abstract class IntermediaryHandler extends SimpleChannelInboundHandler<Object> {

        private final Queue<Object> received = new ArrayDeque<>();

        private boolean finished;
        private Channel backend;

        @Override
        protected final void channelRead0(final ChannelHandlerContext ctx, Object msg) throws Exception {
            if (finished) {
                received.add(ReferenceCountUtil.retain(msg));
                flush();
                return;
            }

            boolean finished = handleProxyProtocol(ctx, msg);
            if (finished) {
                this.finished = true;
                ChannelFuture f = connectToDestination(ctx.channel().eventLoop(), new BackendHandler(ctx));
                f.addListener((ChannelFutureListener) future -> {
                    if (!future.isSuccess()) {
                        recordException(future.cause());
                        ctx.close();
                    } else {
                        backend = future.channel();
                        flush();
                    }
                });
            }
        }

        private void flush() {
            if (backend != null) {
                boolean wrote = false;
                for (; ; ) {
                    Object msg = received.poll();
                    if (msg == null) {
                        break;
                    }
                    backend.write(msg);
                    wrote = true;
                }

                if (wrote) {
                    backend.flush();
                }
            }
        }

        protected abstract boolean handleProxyProtocol(ChannelHandlerContext ctx, Object msg) throws Exception;

        protected abstract SocketAddress intermediaryDestination();

        private ChannelFuture connectToDestination(EventLoop loop, ChannelHandler handler) {
            Bootstrap b = new Bootstrap();
            b.channel(NioSocketChannel.class);
            b.group(loop);
            b.handler(handler);
            return b.connect(intermediaryDestination());
        }

        @Override
        public final void channelReadComplete(ChannelHandlerContext ctx) {
            ctx.flush();
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            if (backend != null) {
                backend.close();
            }
        }

        @Override
        public final void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            recordException(cause);
            ctx.close();
        }

        private final class BackendHandler extends ChannelInboundHandlerAdapter {

            private final ChannelHandlerContext frontend;

            BackendHandler(ChannelHandlerContext frontend) {
                this.frontend = frontend;
            }

            @Override
            public void channelRead(ChannelHandlerContext ctx, Object msg) {
                frontend.write(msg);
            }

            @Override
            public void channelReadComplete(ChannelHandlerContext ctx) {
                frontend.flush();
            }

            @Override
            public void channelInactive(ChannelHandlerContext ctx) {
                frontend.close();
            }

            @Override
            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                recordException(cause);
                ctx.close();
            }
        }
    }

    protected abstract class TerminalHandler extends SimpleChannelInboundHandler<Object> {

        private boolean finished;

        @Override
        protected final void channelRead0(ChannelHandlerContext ctx, Object msg) throws Exception {
            if (finished) {
                String str = ((ByteBuf) msg).toString(CharsetUtil.US_ASCII);
                if ("A\n".equals(str)) {
                    ctx.write(Unpooled.copiedBuffer("1\n", CharsetUtil.US_ASCII));
                } else if ("B\n".equals(str)) {
                    ctx.write(Unpooled.copiedBuffer("2\n", CharsetUtil.US_ASCII));
                } else if ("C\n".equals(str)) {
                    ctx.write(Unpooled.copiedBuffer("3\n", CharsetUtil.US_ASCII))
                            .addListener(ChannelFutureListener.CLOSE);
                } else {
                    throw new IllegalStateException("unexpected message: " + str);
                }
                return;
            }

            this.finished = handleProxyProtocol(ctx, msg);
        }

        protected abstract boolean handleProxyProtocol(ChannelHandlerContext ctx, Object msg) throws Exception;

        @Override
        public final void channelReadComplete(ChannelHandlerContext ctx) {
            ctx.flush();
        }

        @Override
        public final void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            recordException(cause);
            ctx.close();
        }
    }

    private final class HttpIntermediaryHandler extends IntermediaryHandler {

        private SocketAddress intermediaryDestination;

        @Override
        protected boolean handleProxyProtocol(ChannelHandlerContext ctx, Object msg) {
            FullHttpRequest req = (FullHttpRequest) msg;
            FullHttpResponse res;
            if (!authenticate(ctx, req)) {
                res = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.UNAUTHORIZED);
                res.headers().set(HttpHeaderNames.CONTENT_LENGTH, 0);
            } else {
                res = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
                String uri = req.uri();
                int lastColonPos = uri.lastIndexOf(':');

                if (lastColonPos <= 0) {
                    throw new IllegalArgumentException("Invalid URI: " + uri);
                }

                intermediaryDestination = SocketUtils.socketAddress(
                        uri.substring(0, lastColonPos), Integer.parseInt(uri.substring(lastColonPos + 1)));
            }

            ctx.write(res);
            ctx.pipeline().get(HttpServerCodec.class).removeOutboundHandler();
            return true;
        }

        @Override
        protected SocketAddress intermediaryDestination() {
            return intermediaryDestination;
        }
    }

    private final class HttpTerminalHandler extends TerminalHandler {

        @Override
        protected boolean handleProxyProtocol(ChannelHandlerContext ctx, Object msg) {
            FullHttpRequest req = (FullHttpRequest) msg;
            FullHttpResponse res;
            boolean sendGreeting = false;

            if (!authenticate(ctx, req)) {
                res = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.UNAUTHORIZED);
                res.headers().set(HttpHeaderNames.CONTENT_LENGTH, 0);
            } else if (!req.uri().equals(destination.getHostString() + ':' + destination.getPort())) {
                res = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN);
                res.headers().set(HttpHeaderNames.CONTENT_LENGTH, 0);
            } else {
                res = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
                sendGreeting = true;
            }

            ctx.write(res);
            ctx.pipeline().get(HttpServerCodec.class).removeOutboundHandler();

            if (sendGreeting) {
                ctx.write(Unpooled.copiedBuffer("0\n", CharsetUtil.US_ASCII));
            }

            return true;
        }
    }

    private static final class UnresponsiveHandler extends SimpleChannelInboundHandler<Object> {

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, Object msg) {
            // ignore
        }
    }

    public enum TestMode {

        INTERMEDIARY,
        TERMINAL,
        UNRESPONSIVE
    }
}