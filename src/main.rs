#[macro_use]
extern crate env_logger;
extern crate tor_controller;
extern crate socks;
extern crate rustylinez;
extern crate rand;

use tor_controller::control::{Controller, OnionKey, KeyType, AddOnion};
use tor_controller::process::TorProcess;
use rustylinez::completion::FilenameCompleter;
use rustylinez::error::ReadlineError;
use rustylinez::{Editor, Printer};
use std::time::Duration;
use socks::Socks5Stream;
use std::io::{Read, Write, ErrorKind};
use std::fs::{File, OpenOptions};
use std::thread;
use std::thread::JoinHandle;
use std::sync::{RwLock, Arc};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::collections::HashMap;
use std::io::{BufReader, BufRead, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::fmt;
use rand::Rng;

// Print messages using colors (by using terminal scape codes
macro_rules! colorize {
    ($col:expr, $msg:expr) => (concat!("\x1b[38;5;", $col, "m", $msg, "\x1b[0m"));
}

// Print messages concurrently with the handler given by rustylinez, in color
macro_rules! print_color {
    ($pl:expr, $col:expr, $fmt:expr) => ($pl(format!(colorize!($col,  $fmt))));
    ($pl:expr, $col:expr, $fmt:expr, $($arg:tt)*) => ($pl(format!(colorize!($col, $fmt), $($arg)*)));
}

macro_rules! print_normal {
    ($pl:expr, $fmt:expr) => ($pl(format!($fmt)));
    ($pl:expr, $fmt:expr, $($arg:tt)*) => ($pl(format!($fmt, $($arg)*)));
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
    ($pl:expr, $name:expr, $msg:expr) => (print_msg!($pl, 201, $name, $msg));
}

macro_rules! print_msg_them {
    ($pl:expr, $name:expr, $msg:expr) => (print_msg!($pl, 51, $name, $msg));
}

// User unique ID, corresponds to the Onion service id (which is a hash of the key pair)
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
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

    fn to_onion(&self) -> String {
        format!("{}.onion", self)
    }
}

// Stores information about a friend in the friendlist, with a thread handler that handles the
// connection to this friend.
struct Friend {
    id: Id,
    nickname: String,
    tx: Sender<FriendCmd>,
    is_online: Arc<RwLock<bool>>,
    handler: JoinHandle<()>,
}

// Stores the list of friends and maintains consistency with the friend list file friends.txt
struct FriendList {
    map: HashMap<String, Friend>,
    nicknames: Vec<String>,
    map_id_nickname: HashMap<Id, String>,
    own_id: Id,
    file: File,
    main_tx: Sender<Cmd>,
}

impl FriendList {
    fn new(path: &str, id: Id, main_tx: Sender<Cmd>) -> FriendList {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .unwrap();
        let file_lines = {
            let file_reader = BufReader::new(&file);
            file_reader.lines().map(|l| l.unwrap()).collect::<Vec<_>>()
        };
        let mut friend_list = FriendList {
            map: HashMap::new(),
            nicknames: Vec::new(),
            map_id_nickname: HashMap::new(),
            own_id: id,
            file: file,
            main_tx: main_tx,
        };
        {
            for line in file_lines {
                let friend = line.trim().split(' ').collect::<Vec<_>>();
                if friend.len() < 2 {
                    continue;
                }
                let id = Id::from_slice(friend[0].as_bytes()).unwrap();
                let nickname = friend[1];
                friend_list.add_friend(id, nickname.to_string(), false);
            }
        }
        return friend_list;
    }

    fn add_friend(&mut self, id: Id, nickname: String, new: bool) -> bool {
        if self.nicknames.contains(&nickname) {
            return false;
        }
        let nickname1 = nickname.clone();
        self.nicknames.push(nickname1);
        let is_online = Arc::new(RwLock::new(false));
        let (tx, rx) = channel();
        let is_online1 = is_online.clone();
        let tx1 = tx.clone();
        let id1 = id.clone();
        let own_id1 = self.own_id.clone();
        let nickname1 = nickname.clone();
        let main_tx = self.main_tx.clone();
        let handler = thread::spawn(move || {
            friend_handler(own_id1, id1, nickname1, tx1, rx, main_tx, is_online1);
        });
        let friend = Friend {
            id: id.clone(),
            nickname: nickname.clone(),
            tx: tx,
            is_online: is_online,
            handler: handler,
        };
        self.map.insert(nickname.clone(), friend);
        self.map_id_nickname.insert(id.clone(), nickname.clone());
        if new {
            self.file.write_all(format!("{} {}\n", id, nickname).as_bytes()).unwrap();
            self.file.flush().unwrap();
        }
        true
    }
}

// Used to communicate to the friend handler
#[derive(Debug)]
enum FriendCmd {
    SendMsg(String),
    Connected(TcpStream),
    Disconnected,
}

// Used to communicate to the main handler (these represent the main events)
#[derive(Debug)]
enum Cmd {
    SendMsg(String),
    Chat(String),
    Add(Id, String),
    List,
    Quit,
    UnknownConnection(TcpStream),
    NewConnection(Id, TcpStream),
    FriendConnect(String),
    FriendDisconnect(String),
    RecvMsg(String, String),
    InfoMsg(String),
}

// Keep trying to connect to friend_id.onion, return the TcpStream after a connection has been
// stablished.  Whoever has the smallest id acts as hidden service in the returned connection.
fn connect_friend(own_id: Id,
                  friend_id: Id,
                  rx: &Receiver<FriendCmd>) -> TcpStream {
        loop {
            //println!("Trying to connecto to {}", friend_id);
            match Socks5Stream::connect(("127.0.0.1", 9060),
                                        (format!("{}", friend_id.to_onion()).as_str(), 9876)) {
                Ok(stream_out) => {
                    //println!("Connected to {}!", friend_id);
                    // First we send our id
                    let mut stream_out = stream_out.into_inner();
                    stream_out.write_all(format!("{}\n", own_id).as_bytes()).unwrap();
                    stream_out.flush().unwrap();
                    if own_id < friend_id {
                        // We use our connection to their hidden service.  They authenticate us.
                        // We just echo the secret we receive from our connection to the connection
                        // they made.
                        match rx.recv().unwrap() {
                            FriendCmd::Connected(mut stream_in) => {
                                let mut buffer = [0 as u8; 32];
                                //println!("Reciving a secret from {}", friend_id);
                                if let Err(_) = stream_in.read_exact(&mut buffer) {
                                    continue;
                                }
                                //println!("Sending a secret to {}", friend_id);
                                if let Err(_) = stream_out.write_all(&buffer) {
                                    continue;
                                }
                                return stream_out;
                            },
                            _ => (),
                        }
                    } else {
                        // We use their connection to our hidden service.  We authenticate them.
                        // To authenticate, we send a random secret to the connection we made and
                        // expect the same secret back from the connection they made.
                        //println!("Waiting connection from {}", friend_id);
                        match rx.recv().unwrap() {
                            FriendCmd::Connected(mut stream_in) => {
                                //println!("{} connected to us!", friend_id);
                                let mut rng = rand::thread_rng();
                                let secret = rng.gen::<[u8; 32]>();
                                //println!("Sending a secret to {}", friend_id);
                                if let Err(_) = stream_out.write_all(&secret) {
                                    continue;
                                }
                                let mut buffer = [0 as u8; 32];
                                //println!("Reciving a secret from {}", friend_id);
                                if let Err(_) = stream_in.read_exact(&mut buffer) {
                                    continue;
                                }
                                if secret == buffer {
                                    //println!("Secret from {} matches!", friend_id);
                                    return stream_in;
                                }
                            }
                            _ => (),
                        }
                    }
                },
                Err(_) => (),
            }
            thread::sleep(Duration::from_secs(5));
        }
}

// Handle the connection to a friend, and notify the main handler when they are online/offline.
fn friend_handler(own_id: Id,
                  friend_id: Id,
                  nickname: String,
                  tx: Sender<FriendCmd>,
                  rx: Receiver<FriendCmd>,
                  main_tx: Sender<Cmd>,
                  is_online: Arc<RwLock<bool>>) {
    let mut rx = rx;
    let mut tx = tx;
    let mut main_tx = main_tx;
    loop {
        let stream = connect_friend(own_id, friend_id, &rx);

        let reader = BufReader::new(stream.try_clone().unwrap());
        let mut writer = BufWriter::new(stream.try_clone().unwrap());
        *is_online.write().unwrap() = true;
        main_tx.send(Cmd::FriendConnect(nickname.clone())).unwrap();

        let nickname1 = nickname.clone();
        let reader_handler = thread::spawn(move || {
            for line in reader.lines() {
                main_tx.send(Cmd::RecvMsg(nickname1.clone(), line.unwrap())).unwrap();
            }
            tx.send(FriendCmd::Disconnected).unwrap();
            return (main_tx, tx);
        });

        let writer_handler = thread::spawn(move || {
            for friend_cmd in &rx {
                match friend_cmd {
                    FriendCmd::SendMsg(msg) => {
                        writer.write_all(msg.as_bytes()).unwrap();
                        writer.write_all(b"\n").unwrap();
                        writer.flush().unwrap();
                    },
                    FriendCmd::Disconnected => {
                        break;
                    },
                    _ => (),
                }
            }
            return rx;
        });

        rx = writer_handler.join().unwrap();
        let (main_tx1, tx1) =  reader_handler.join().unwrap();
        main_tx = main_tx1;
        tx = tx1;

        *is_online.write().unwrap() = false;
        main_tx.send(Cmd::FriendDisconnect(nickname.clone())).unwrap();
    }
}

fn main_handler(printer: Printer, rx: Receiver<Cmd>, tx: Sender<Cmd>) {
    let mut pr = printer.clone();
    let mut pl = move |s| pr.println(s);
    info!(pl, "Starting Tor Daemon...");
    let mut tor = TorProcess::new();
    tor.torrc_path("torrc").timeout(30).launch().unwrap();

    info!(pl, "Connecting to Tor controller...");
    let mut controller = Controller::from_port(9061).unwrap();
    controller.authenticate().unwrap();

    // We read the private key from key.txt or generate a new one if it doesn't exist.
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
    let own_id = Id::from_slice(add_onion_rep.service_id.as_bytes()).unwrap();
    info!(pl, "Your ID is: {}", own_id);
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

    // This thread keeps listening for incomming connection and sends them to the main handler.
    let tx1 = tx.clone();
    thread::spawn(move || {
        let listener = TcpListener::bind(("127.0.0.1", 9876)).unwrap();
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    //println!("Someone has tried connecting to us!");
                    tx1.send(Cmd::UnknownConnection(stream)).unwrap();
                }
                Err(e) => (),
            }
        }
    });

    let mut current_chat_nickname: Option<String> = None;
    let tx1 = tx.clone();
    let mut friend_list = FriendList::new("friends.txt", own_id, tx1);
    // This is the main handler loop, listening for events.
    loop {
        match rx.recv().unwrap() {
            Cmd::SendMsg(msg) => {
                // Send a message to the current selected nickname.
                if msg == "" {
                    continue;
                }
                if let Some(ref nickname) = current_chat_nickname {
                    let friend = friend_list.map.get_mut(nickname).unwrap();
                    friend.tx.send(FriendCmd::SendMsg(msg.clone())).unwrap();
                    print_msg_me!(pl, "Me", msg);
                }
            }
            Cmd::Add(id, nickname) => {
                // Add a new friend to the friend_list.
                if !friend_list.add_friend(id, nickname.clone(), true) {
                    error!(pl, "Error adding friend: nickname {} already found in your list",
                           nickname);
                }
            }
            Cmd::Chat(nickname) => {
                // Select a friend to chat.
                if !friend_list.map.contains_key(&nickname) {
                    error!(pl, "No friend found with nickname {}", nickname);
                    continue;
                }
                if !*friend_list.map.get(&nickname).unwrap().is_online.read().unwrap() {
                    error!(pl, "{} is currently offline", nickname);
                    continue;
                }
                current_chat_nickname = Some(nickname.clone());
                info!(pl, "Currently chatting with {}", nickname);
            },
            Cmd::List => {
                // List the friend_list, separating online and offline friends.
                let online = friend_list.nicknames.iter().map(|n| friend_list.map.get(n).unwrap())
                    .filter(|f| *f.is_online.read().unwrap())
                    .map(|f| format!("{} {}", f.id, f.nickname)).collect::<Vec<_>>();
                let offline = friend_list.nicknames.iter().map(|n| friend_list.map.get(n).unwrap())
                    .filter(|f| !*f.is_online.read().unwrap())
                    .map(|f| format!("{} {}", f.id, f.nickname)).collect::<Vec<_>>();
                print_normal!(pl, "Online:");
                for friend in online {
                    print_normal!(pl, "\t{}", friend);
                }
                print_normal!(pl, "Offline:");
                for friend in offline {
                    print_normal!(pl, "\t{}", friend);
                }
            },
            Cmd::UnknownConnection(mut stream) => {
                // Someone has connected to us, handle this connection.
                let tx1 = tx.clone();
                thread::spawn(move ||{
                    let mut buffer = [0; 17];
                    stream.read_exact(&mut buffer).unwrap();
                    let id = Id::from_slice(&buffer[..16]).unwrap();
                    tx1.send(Cmd::NewConnection(id, stream)).unwrap();
                    //println!("This someone claims to be {}", id);
                });
            },
            Cmd::NewConnection(id, stream) => {
                match friend_list.map_id_nickname.get(&id) {
                    Some(nickname) => {
                        //info!(pl, "{} connected", nickname);
                        let friend = friend_list.map.get_mut(nickname).unwrap();
                        friend.tx.send(FriendCmd::Connected(stream)).unwrap();
                    },
                    None => info!(pl, "{} tried to connect, \
                                  but is not in the friends list", id),
                }
            }
            Cmd::FriendConnect(nickname) => {
                // Notify that we connected to a friend succesfully.
                info!(pl, "{} is online", nickname);
            },
            Cmd::FriendDisconnect(nickname) => {
                // Notify that we lost communication to a friend.
                info!(pl, "{} is offline", nickname);
                if Some(nickname) == current_chat_nickname {
                    current_chat_nickname = None;
                }
            }
            Cmd::RecvMsg(nickname, msg) => {
                // We receive a message from nickname (this comes from the friend_handler).
                if current_chat_nickname.is_none() {
                    tx.send(Cmd::Chat(nickname.clone())).unwrap();
                }
                print_msg_them!(pl, nickname, msg);
            },
            Cmd::InfoMsg(msg) => {
                // Show an information message
                info!(pl, "{}", msg);
            }
            Cmd::Quit => break,
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
    let main_handler_thread = thread::spawn(move || {
        thread::sleep(Duration::from_secs(1));
        main_handler(rl_printer, rx, tx1);
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
                                    tx.send(Cmd::Add(id, args[2].to_string()))
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

    main_handler_thread.join().unwrap();
}
