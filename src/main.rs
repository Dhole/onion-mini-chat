#[macro_use]
extern crate env_logger;
extern crate tor_controller;
extern crate socks;
extern crate rustylinez;
extern crate colored;

use tor_controller::control::{Controller, OnionKey, KeyType, OnionFlags, AddOnion};
use tor_controller::process::TorProcess;
use rustylinez::completion::FilenameCompleter;
use rustylinez::error::ReadlineError;
use rustylinez::{Editor, Input, Printer};
use colored::*;
use std::time::Duration;
use socks::Socks5Stream;
use std::io::{Read, Write, ErrorKind};
use std::fs::File;
use std::thread;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::collections::HashMap;
use std::io::{BufReader, BufRead, BufWriter};
use std::net::TcpListener;
use std::fmt;

#[derive(Debug, PartialEq, Eq, PartialOrd, Hash, Clone)]
struct Id([u8; 16]);

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}

impl Id {
    fn from_slice(s: &[u8]) -> Option<Self> {
        if s.len() != 16 {
            None
        } else {
            let mut id = Id([0; 16]);
            for i in 0..16 {
                id.0[i] = s[i];
            }
            Some(id)
        }
    }
}

#[derive(Debug)]
enum Cmd {
    SendMsg(String),
    Chat(String),
    Add(Id, String),
    List,
    Quit,
    PeerConnect(String),
    PeerDisconnect(String),
    RecvMsg(String, String),
}

macro_rules! colorize {
    ($col:expr, $msg:expr) => (concat!("\x1b[38;5;", $col, "m", $msg, "\x1b[0m"));
}

macro_rules! print_color {
    ($pl:expr, $col:expr, $fmt:expr) => ($pl(format!(colorize!($col,  $fmt))));
    ($pl:expr, $col:expr, $fmt:expr, $($arg:tt)*) => ($pl(format!(colorize!($col, $fmt), $($arg)*)));
}

macro_rules! info {
    ($pl:expr, $($arg:tt)*) => (print_color!($pl, 244, $($arg)*));
}

macro_rules! error {
    ($pl:expr, $($arg:tt)*) => (print_color!($pl, 196, $($arg)*));
}

macro_rules! print_msg {
    ($pl:expr, $col:expr, $name:expr, $msg:expr) => ($pl(format!(concat!(colorize!($col,  "{}"), ": {}"), $name, $msg)));
}

macro_rules! print_msg_me {
    ($pl:expr, $name:expr, $msg:expr) => (print_msg!($pl, 51, $name, $msg));
}

macro_rules! print_msg_them {
    ($pl:expr, $name:expr, $msg:expr) => (print_msg!($pl, 201, $name, $msg));
}

fn tor_handler(printer: Printer, rx: Receiver<Cmd>, tx: Sender<Cmd>) {
    let mut pr = printer.clone();
    let mut pl = move |s| pr.println(s);
    info!(pl, "Starting Tor Daemon...");
    let mut tor = TorProcess::new();
    tor.torrc_path("torrc").timeout(30).launch().unwrap();

    info!(pl, "Connecting to Tor controller...");
    let mut controller = Controller::from_port(9061).unwrap();
    controller.authenticate().unwrap();

    // thread::spawn(move || {
    //    let mut pr = printer.clone();
    //    let mut pl = move |s| pr.println(s);
    //    loop {
    //        thread::sleep(Duration::from_secs(2));
    //        print_msg_me!(pl, "Dhole", "OLA K ASE");
    //    }
    // });

    // let mut con = Socks5Stream::connect(("127.0.0.1", 9060), ("cripticavraowaqb.onion", 80))
    //    .unwrap();

    let mut new_key = false;
    let onion_key = match File::open("key.txt") {
        Ok(ref mut key_file) => {
            let mut key = String::new();
            key_file.read_to_string(&mut key).unwrap();
            OnionKey::Rsa1024(key)
        }
        Err(err) => {
            match err.kind() {
                ErrorKind::NotFound => {
                    info!(pl, "No key file key.txt found, generating a new key...");
                    new_key = true;
                    OnionKey::New(KeyType::Best)
                }
                err => {
                    error!(pl, "Error opening key file key.txt: {:?}", err);
                    return;
                }
            }
        }
    };

    info!(pl, "Launching Onion service...");
    let add_onion = AddOnion {
        key: onion_key,
        flags: vec![],
        ports: vec![(9876, None)],
        client_auths: vec![],
    };
    let add_onion_rep = controller.cmd_add_onion(add_onion).unwrap();
    info!(pl, "Your ID is: {}", add_onion_rep.service_id);
    if new_key {
        match File::create("key.txt") {
            Ok(ref mut key_file) => {
                key_file.write_all(add_onion_rep.sk.unwrap().as_bytes()).unwrap();
            }
            Err(err) => {
                error!(pl, "Error creating key file key.txt: {:?}", err);
                return;
            }
        }
    }
    let tx1 = tx.clone();
    thread::spawn(move || {
        let listener = TcpListener::bind(("127.0.0.1", 9876)).unwrap();
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let con_r = BufReader::new(stream);
                    for line in con_r.lines() {
                        tx1.send(Cmd::RecvMsg("Unknown".to_string(), line.unwrap())).unwrap();
                    }
                }
                Err(e) => println!("Connection failed {:?}", e),
            }
        }
    });
    let mut current_chat_id: Option<Id> = None;
    let mut connected_peers = HashMap::new();
    let mut nicknames = HashMap::new();
    loop {
        match rx.recv().unwrap() {
            Cmd::SendMsg(msg) => {
                if let Some(ref id) = current_chat_id {
                    let tx: &Sender<String> = connected_peers.get_mut(id).unwrap();
                    tx.send(msg.clone()).unwrap();
                    print_msg_me!(pl, "Me", msg);
                }
            }
            Cmd::Add(id, nickname) => {
                let (peer_tx, peer_rx) = channel();
                let tx = tx.clone();
                let id1 = id.clone();
                let nickname1 = nickname.clone();
                thread::spawn(move || {
                    let con_r = Socks5Stream::connect(("127.0.0.1", 9060),
                                                      (format!("{}.onion", id1).as_str(), 9876))
                        .unwrap()
                        .into_inner();
                    let mut con_w = con_r.try_clone().unwrap();
                    let reader = thread::spawn(move || {
                        let con_r = BufReader::new(con_r);
                        for line in con_r.lines() {
                            tx.send(Cmd::RecvMsg(nickname1.clone(), line.unwrap())).unwrap();
                        }
                    });
                    let writer = thread::spawn(move || {
                        loop {
                            let msg: String = peer_rx.recv().unwrap();
                            con_w.write_all(msg.as_bytes()).unwrap();
                            con_w.write_all(b"\n").unwrap();
                            con_w.flush().unwrap();
                        }
                    });
                });
                current_chat_id = Some(id.clone());
                connected_peers.insert(id.clone(), peer_tx);
                nicknames.insert(nickname, id);
            }
            Cmd::Chat(nickname) => unimplemented!(),
            Cmd::List => unimplemented!(),
            Cmd::Quit => break,
            Cmd::PeerConnect(id) => unimplemented!(),
            Cmd::PeerDisconnect(id) => unimplemented!(),
            Cmd::RecvMsg(nickname, msg) => print_msg_them!(pl, nickname, msg),
        }
    }
}

fn main() {
    env_logger::init().unwrap();

    println!("\x1b[2J");

    let c = FilenameCompleter::new();
    let mut rl = Editor::new();
    rl.set_completer(Some(&c));
    let rl_printer = rl.get_printer();

    let (tx, rx) = channel();

    let tx1 = tx.clone();
    let tor_handler_thread = thread::spawn(move || {
        thread::sleep(Duration::from_secs(1));
        tor_handler(rl_printer, rx, tx1);
    });

    // let readline_thread = thread::spawn(move || {
    let prompt = "> ";
    loop {
        let readline = rl.readline(prompt);
        match readline {
            Ok(line) => {
                rl.add_history_entry(&line);
                if line.chars().nth(0) == Some('/') {
                    println!("{}{}", prompt, line);
                    let args = line.split(' ').collect::<Vec<_>>();
                    match args[0] {
                        "/chat" => {
                            if args.len() == 2 {
                                tx.send(Cmd::Chat(args[1].to_string())).unwrap();
                                continue;
                            }
                            println!("usage: /chat nickname");
                        }
                        "/add" => {
                            if args.len() == 3 {
                                if let Some(id) = Id::from_slice(args[1].as_bytes()) {
                                    tx.send(Cmd::Add(id, args[1].to_string()))
                                        .unwrap();
                                    continue;
                                }
                            }
                            println!("usage: /add id nickname");
                        }
                        "/list" => tx.send(Cmd::List).unwrap(),
                        "/help" => {
                            println!("Possible commads are:\n\
                                   \t/chat nickname\n\
                                   \t/add id nickname\n\
                                   \t/list\n\
                                   \t/quit\n\
                                   \t/help");
                        }
                        "/quit" => {
                            tx.send(Cmd::Quit).unwrap();
                            break;
                        },
                        _ => println!("Unrecognized command: {}", line),
                    }
                } else {
                    tx.send(Cmd::SendMsg(line)).unwrap();
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                tx.send(Cmd::Quit).unwrap();
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                tx.send(Cmd::Quit).unwrap();
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                tx.send(Cmd::Quit).unwrap();
                break;
            }
        }
    }
    // });

    tor_handler_thread.join().unwrap();
}
