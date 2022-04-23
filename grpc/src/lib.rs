use anyhow::Result;
use futures::{FutureExt, StreamExt, TryFutureExt, TryStreamExt};
use hello_world::{
    greeter_client::GreeterClient,
    greeter_server::{Greeter, GreeterServer},
    HelloReply, HelloReplyBytes, HelloRequest, HelloRequestBytes,
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
        assert!(request.peer_certs().is_some());
        println!("Got a request from {:?}", request.remote_addr());

        let reply = hello_world::HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };
        Ok(Response::new(reply))
    }

    async fn say_hello_bytes(
        &self,
        _: tonic::Request<hello_world::HelloRequestBytes>,
    ) -> Result<Response<HelloReplyBytes>, Status> {
        Err(Status::aborted("TODO"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn it_works() -> Result<()> {
        let (addr, server) = server()?;
        tokio::spawn(server);
        client(addr).await?;

        Ok(())
    }
}
