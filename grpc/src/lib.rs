use anyhow::Result;
use futures::{FutureExt, StreamExt, TryFutureExt, TryStreamExt};
use hello_world::{
    greeter_client::GreeterClient,
    greeter_server::{Greeter, GreeterServer},
    HelloReply, HelloRequest,
};
use hyper::{client::HttpConnector, Uri};
use rustls::Certificate;
use std::{
    future::Future,
    io,
    net::{SocketAddr, TcpListener},
    pin::Pin,
    process::Output,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{
    rustls::{ClientConfig, RootCertStore},
    server::TlsStream,
    TlsAcceptor,
};
use tonic::{
    transport::{server::Connected, Channel, ClientTlsConfig, Endpoint, Server, ServerTlsConfig},
    Request, Response, Status,
};

mod crypto;
use crypto::Config;

pub mod hello_world {
    tonic::include_proto!("helloworld");
}

#[derive(Default)]
pub struct MyGreeter {}

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        println!("Got a request from {:?}", request.remote_addr());

        let reply = hello_world::HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };
        Ok(Response::new(reply))
    }
}

fn server() -> Result<(
    SocketAddr,
    impl Future<Output = Result<(), tonic::transport::Error>>,
)> {
    let config = Config::random()?;
    let addr = "localhost:0";
    let listener = TcpListener::bind(addr)?;
    // let listener = TcpListener::bind("[::1]:50051")?;
    let local_addr = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let listener = tokio_stream::wrappers::TcpListenerStream::new(
        tokio::net::TcpListener::from_std(listener)?,
    );
    // let tls_acceptor = TlsAcceptor::from(Arc::new(config.server));
    // let listener = listener.and_then(move |stream| tls_acceptor.accept(stream));

    println!("GreeterServer listening on {}", local_addr);
    let greeter = MyGreeter::default();
    let server = Server::builder()
        .tls_config(ServerTlsConfig::new().rustls_server_config(config.server))?
        .add_service(GreeterServer::new(greeter));
    let server = server.serve_with_incoming(listener);

    Ok((local_addr, server))
}

async fn client(addr: SocketAddr) -> Result<()> {
    let config = Config::random()?;
    let tls = ClientTlsConfig::new()
        .rustls_client_config(config.client)
        // .domain_name("example.com");
        .domain_name("foo");

    let url = format!("https://{}", addr);
    let channel = Channel::from_shared(url)?
        .tls_config(tls)?
        .connect()
        .await?;

    let mut client = GreeterClient::new(channel);

    let request = tonic::Request::new(HelloRequest {
        name: "Tonic".into(),
    });

    let response = client.say_hello(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}

fn server_tls() -> Result<impl Future<Output = Result<(), tonic::transport::Error>>> {
    let config = Config::random()?;
    let addr = "localhost:0";
    // let listener = TcpListener::bind(addr)?;
    let listener = TcpListener::bind("[::1]:50051")?;
    let local_addr = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let listener = tokio_stream::wrappers::TcpListenerStream::new(
        tokio::net::TcpListener::from_std(listener)?,
    );
    let tls = config.server;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls));

    let listener = listener.and_then(move |stream| {
        tls_acceptor
            .accept(stream)
            .map_ok(|stream| MyTlsStream(stream))
    });

    println!("GreeterServer listening on {}", local_addr);
    let greeter = MyGreeter::default();
    let server = Server::builder().add_service(GreeterServer::new(greeter));
    let server = server.serve_with_incoming(listener);

    Ok(server)
}

struct MyTlsStream<T>(TlsStream<T>);

impl<T> Connected for MyTlsStream<T>
where
    T: Connected,
{
    type ConnectInfo = TlsConnectInfo<T::ConnectInfo>;

    fn connect_info(&self) -> Self::ConnectInfo {
        let (inner, session) = self.0.get_ref();
        let inner = inner.connect_info();

        let certs = if let Some(certs) = session.peer_certificates() {
            let certs = certs.iter().cloned().collect();
            Some(Arc::new(certs))
        } else {
            None
        };

        TlsConnectInfo { inner, certs }
    }
}

impl<IO> AsyncRead for MyTlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<IO> AsyncWrite for MyTlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Note: that it does not guarantee the final data to be sent.
    /// To be cautious, you must manually call `flush`.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone)]
pub struct TlsConnectInfo<T> {
    inner: T,
    certs: Option<Arc<Vec<Certificate>>>,
}

impl<T> TlsConnectInfo<T> {
    /// Get a reference to the underlying connection info.
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the underlying connection info.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Return the set of connected peer TLS certificates.
    pub fn peer_certs(&self) -> Option<Arc<Vec<Certificate>>> {
        self.certs.clone()
    }
}

async fn client_tls() -> Result<()> {
    let config = Config::random()?;
    let tls = config.client;

    let mut http = HttpConnector::new();
    http.enforce_http(false);

    // We have to do some wrapping here to map the request type from
    // `https://example.com` -> `https://[::1]:50051` because `rustls`
    // doesn't accept ip's as `ServerName`.
    let connector = tower::ServiceBuilder::new()
        .layer_fn(move |s| {
            let tls = tls.clone();

            hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(tls)
                .https_or_http()
                .enable_http2()
                .wrap_connector(s)
        })
        // Since our cert is signed with `example.com` but we actually want to connect
        // to a local server we will override the Uri passed from the `HttpsConnector`
        // and map it to the correct `Uri` that will connect us directly to the local server.
        .map_request(|_| Uri::from_static("https://[::1]:50051"))
        .service(http);

    // let client = hyper::Client::builder().build(connector);

    // Hyper expects an absolute `Uri` to allow it to know which server to connect too.
    // Currently, tonic's generated code only sets the `path_and_query` section so we
    // are going to write a custom tower layer in front of the hyper client to add the
    // scheme and authority.
    //
    // Again, this Uri is `example.com` because our tls certs is signed with this SNI but above
    // we actually map this back to `[::1]:50051` before the `Uri` is passed to hyper's `HttpConnector`
    // to allow it to correctly establish the tcp connection to the local `tls-server`.
    // let uri = Uri::from_static("https://example.com");
    let uri = Uri::from_static("https://foo");
    // let uri = Uri::from_static("https://[::1]:50051");
    // let svc = tower::ServiceBuilder::new()
    //     .map_request(move |mut req: http::Request<tonic::body::BoxBody>| {
    //         let uri = Uri::builder()
    //             .scheme(uri.scheme().unwrap().clone())
    //             .authority(uri.authority().unwrap().clone())
    //             .path_and_query(req.uri().path_and_query().unwrap().clone())
    //             .build()
    //             .unwrap();

    //         *req.uri_mut() = uri;
    //         req
    //     })
    //     .service(client);
    let channel = Endpoint::try_from(uri)?
        .connect_with_connector(connector)
        .await?;

    let mut client = GreeterClient::new(channel);
    let request = tonic::Request::new(HelloRequest {
        name: "Tonic".into(),
    });
    let response = client.say_hello(request).await?;

    println!("RESPONSE={:?}", response);
    Ok(())
}

#[cfg(test)]
mod tests {
    use futures::future::join;

    use super::*;

    #[tokio::test]
    async fn it_works() -> Result<()> {
        let (addr, server) = server()?;
        tokio::spawn(server);
        client(addr).await?;

        Ok(())
    }

    #[tokio::test]
    async fn tls() -> Result<()> {
        let server = server_tls().unwrap();
        tokio::spawn(server);
        client_tls().await.unwrap();

        Ok(())
    }
}
