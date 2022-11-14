// SPDX-License-Identifier: MIT

use crate::watch::SockWatch;

mod watch;

//use netlink_packet_sock_diag::{
//    constants::*,
//    inet::{nlas::Nla, ExtensionFlags, InetRequest, SocketId, StateFlags},
//    NetlinkHeader, NetlinkMessage, NetlinkPayload, SockDiagMessage,
//};
//use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};

fn main() {
    let mut sw = SockWatch::new(1000).unwrap();

    sw.scan_sockets();
}

//fn main() {
//    let mut socket = Socket::new(NETLINK_SOCK_DIAG).unwrap();
//    let _port_number = socket.bind_auto().unwrap().port_number();
//    socket.connect(&SocketAddr::new(0, 0)).unwrap();
//
//    let mut packet = NetlinkMessage {
//        header: NetlinkHeader {
//            flags: NLM_F_REQUEST | NLM_F_DUMP,
//            ..Default::default()
//        },
//        payload: SockDiagMessage::InetRequest(InetRequest {
//            family: AF_INET,
//            protocol: IPPROTO_TCP,
//            //            extensions: ExtensionFlags::empty(),
//            extensions: ExtensionFlags::INFO,
//            states: StateFlags::all(),
//            socket_id: SocketId::new_v4(),
//        })
//        .into(),
//    };
//
//    packet.finalize();
//
//    let mut buf = vec![0; packet.header.length as usize];
//
//    // Before calling serialize, it is important to check that the buffer in which
//    // we're emitting is big enough for the packet, other `serialize()` panics.
//    assert_eq!(buf.len(), packet.buffer_len());
//
//    packet.serialize(&mut buf[..]);
//
//    //    println!(">>> {:?}", packet);
//    if let Err(e) = socket.send(&buf[..], 0) {
//        println!("SEND ERROR {}", e);
//        return;
//    }
//
//    let mut receive_buffer = vec![0; 4096];
//    let mut offset = 0;
//    while let Ok(size) = socket.recv(&mut &mut receive_buffer[..], 0) {
//        loop {
//            let bytes = &receive_buffer[offset..];
//            let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes).unwrap();
//            //            println!("<<< {:?}", rx_packet);
//
//            match rx_packet.payload {
//                NetlinkPayload::Noop | NetlinkPayload::Ack(_) => {}
//                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
//                    //                    println!("{:#?}", response);
//                    //                    println!("{:?}", response);
//
//                    let mut entry = String::from("");
//                    entry.push_str(&format!(
//                        "state: {}, uid: {}, inode {}, src: {}:{}, dst: {}:{}",
//                        response.header.state,
//                        response.header.uid,
//                        response.header.inode,
//                        response.header.socket_id.source_address,
//                        response.header.socket_id.source_port,
//                        response.header.socket_id.destination_address,
//                        response.header.socket_id.destination_port
//                    ));
//
//                    println!("{}", entry);
//
//                    for nla in response.nlas {
//                        match nla {
//                            Nla::TcpInfo(val) => {
//                                //                                entry.push_str(&format!("state: {}", val.state));
//                                //                             println!("state: {}", value.state);
//                            }
//                            Nla::Congestion(value) => {
//                                //                              println!("congestion: {:?}", value);
//                            }
//                            _ => {}
//                        }
//                    }
//                }
//                NetlinkPayload::Done => {
//                    println!("Done!");
//                    return;
//                }
//                _ => return,
//            }
//
//            offset += rx_packet.header.length as usize;
//            if offset == size || rx_packet.header.length == 0 {
//                offset = 0;
//                break;
//            }
//        }
//    }
//}
