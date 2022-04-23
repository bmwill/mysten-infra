mod crypto;
pub use crypto::Config;

#[cfg(test)]
mod tests {
    use crate::Config;
    use anyhow::Result;
    use std::{
        future::Future,
        net::{SocketAddr, TcpListener},
    };
    use tonic::{transport::Channel, Request, Response, Status};

    pub mod hello_world {
        tonic::include_proto!("helloworld");
    }
    use hello_world::{
        greeter_client::GreeterClient,
        greeter_server::{Greeter, GreeterServer},
        HelloReply, HelloReplyBytes, HelloRequest,
    };

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

    fn server(
        addr: SocketAddr,
    ) -> Result<(
        SocketAddr,
        impl Future<Output = Result<(), tonic::transport::Error>>,
    )> {
        let config = Config::random("foo")?;
        let listener = TcpListener::bind(addr)?;
        let local_addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let listener = tokio_stream::wrappers::TcpListenerStream::new(
            tokio::net::TcpListener::from_std(listener)?,
        );

        println!("GreeterServer listening on {}", local_addr);
        let greeter = MyGreeter::default();
        let server = config
            .server_builder()?
            .add_service(GreeterServer::new(greeter));
        let server = server.serve_with_incoming(listener);

        Ok((local_addr, server))
    }

    async fn client(addr: SocketAddr) -> Result<()> {
        let channel = client_channel(addr)?;
        client_call(channel).await
    }

    fn client_channel(addr: SocketAddr) -> Result<Channel> {
        let config = Config::random("foo")?;
        config.channel(addr)
    }

    async fn client_call(channel: Channel) -> Result<()> {
        let mut client = GreeterClient::new(channel);

        let request = tonic::Request::new(HelloRequest {
            name: "Tonic".into(),
        });

        let response = client.say_hello(request).await?;

        println!("RESPONSE={:?}", response);
        Ok(())
    }

    #[tokio::test]
    async fn it_works() -> Result<()> {
        let addr = "127.0.0.1:50051".parse().unwrap();
        let channel = client_channel(addr)?;
        client_call(channel.clone()).await.unwrap_err();
        let (addr, server) = server(addr)?;
        tokio::spawn(server);
        client_call(channel.clone()).await?;
        client_call(channel.clone()).await?;
        client_call(channel).await?;
        client(addr).await?;

        Ok(())
    }
}
