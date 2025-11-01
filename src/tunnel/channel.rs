use tokio::sync::mpsc::{Receiver, Sender, error::SendError};

pub struct TunnelManagerChannel {
    sender: Sender<Vec<u8>>,
    receiver: Receiver<Vec<u8>>,
}

impl TunnelManagerChannel {
    pub(super) fn new(sender: Sender<Vec<u8>>, receiver: Receiver<Vec<u8>>) -> Self {
        TunnelManagerChannel { sender, receiver }
    }

    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.receiver.recv().await
    }

    pub async fn send(&self, data: Vec<u8>) -> Result<(), SendError<Vec<u8>>> {
        self.sender.send(data).await
    }
}
