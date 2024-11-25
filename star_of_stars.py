import socket
import threading
import time
import pandas
import os
import sys
import random
from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Set, Optional
from in_files_generator import generate_in_files


class FrameType(Enum):
    DATA = 0
    ACK = 1
    NACK = 2
    FIREWALL_RULES = 3

@dataclass
class Frame:
    src_network: int # network num
    src_node: int # node num
    dst_network: int
    dst_node: int
    frame_type: FrameType
    size: int # max 255
    data: bytes = b''
    
    # converts frame to bytes
    def frame_to_bytes(self):
        header = bytes([
            self.src_network, self.src_node,
            self.dst_network, self.dst_node,
            self.frame_type.value, self.size
        ])
        return header + self.data
    
    # converts bytes to frame
    @classmethod
    def bytes_to_frames(cls, data: bytes):
        src_network = data[0]
        src_node = data[1]
        dst_network = data[2]
        dst_node = data[3]
        frame_type = FrameType(data[4])
        size = data[5]
        payload = data[6:] if size > 0 else b''
        return cls(
            src_network=src_network,
            src_node=src_node,
            dst_network=dst_network,
            dst_node=dst_node,
            frame_type=frame_type,
            size=size,
            data=payload
        )


class FirewallRule:
    def __init__(self, network: int, node: Optional[int] = None, local_only: bool = False):
        self.network = network
        self.node = node
        self.local_only = local_only
    
    @classmethod
    def from_string(cls, rule_str: str):
        try:
            if isinstance(rule_str, dict):
                return cls(
                    network=rule_str['network'],
                    node=rule_str['node'],
                    local_only=rule_str['local_only']
                )
                
            if ':' not in rule_str:
                parts = rule_str.split()
                addr_part = parts[0]
                rule_type = 'local' if len(parts) > 1 and parts[1].lower() == 'local' else ''
            else:
                addr_part, rule_type = [part.strip() for part in rule_str.split(':')]
            
            addr_parts = addr_part.strip().split('_')
            if len(addr_parts) != 2:
                raise ValueError("Invalid address format")
                
            network = int(addr_parts[0])
            
            # node number or None to block
            node_str = addr_parts[1].strip()
            node = None if node_str == '#' else int(node_str)
            
            local_only = rule_type.strip().lower() == 'local'
            
            return cls(network, node, local_only)
            
        except Exception as e:
            print(f"Error parsing firewall rule '{rule_str}': {e}")
            return cls(0, None, False)

    def __str__(self):
        node_part = '#' if self.node is None else str(self.node)
        return f"{self.network}_{node_part}: local" if self.local_only else f"{self.network}_{node_part}"

class CCSShadowSwitch:
    
    def __init__(self, host: str = 'localhost', port: int = 5001):
        self.host = host
        self.port = port
        self.running = True
        self.is_active = False # only activate when main switch stops
        
        # socket setup
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(16)
            print(f"Shadow CCS bound to {self.host}:{self.port}")
        except Exception as e:
            print(f"Error binding Shadow CCS socket: {e}")
            raise
            
        self.active_connections = set()
    
    def start(self):
        self.running = True
        threading.Thread(target=self.run).start()
    
    def run(self):
        print(f"CCS Shadow switch listening on {self.host}:{self.port}")
        while self.running:
            try:
                # check switch working
                if not self.is_active:
                    try:
                        # test connection to main switch
                        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        test_socket.settimeout(1.0)
                        test_socket.connect((self.host, self.port - 1))
                        test_socket.close()
                        time.sleep(1) # wait
                        continue
                    except:
                        print("Main CCS appears to be down, activating shadow switch")
                        self.is_active = True
                
                # when activated
                if self.is_active:
                    self.server_socket.settimeout(1.0)
                    try:
                        conn, addr = self.server_socket.accept()
                        print(f"Shadow CCS: New connection from {addr}")
                        self.active_connections.add(conn)
                        handler = threading.Thread(target=self.handle_cas, args=(conn, addr))
                        handler.daemon = True
                        handler.start()
                    except socket.timeout:
                        continue
                    
            except Exception as e:
                if self.running:
                    print(f"Shadow switch accept error: {e}")
    
    def shutdown(self):
        print("Shadow CCS: Initiating shutdown...")
        self.running = False
        
        for conn in self.active_connections.copy():
            try:
                conn.close()
            except:
                pass
        self.active_connections.clear()
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        print("Shadow CCS: Shutdown complete")

class CCSSwitch(threading.Thread):
    """Central Core Switch with firewall capabilities"""
    
    def __init__(self, host: str = 'localhost', port: int = 5000):
        super().__init__()
        self.host = host
        self.port = port
        self.running = True
        self.frame_buffer: List[Frame] = []
        self.buffer_lock = threading.Lock()
        
        self.forwarding_table: Dict[int, tuple] = {}
        self.forwarding_lock = threading.Lock()
        
        self.firewall_rules: List[FirewallRule] = []
        
        # socket setup
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(16) # 16 networks
            print(f"CCS bound to {self.host}:{self.port}")
        except Exception as e:
            print(f"Error binding CCS socket: {e}")
            raise
        
        self.active_connections = set()
        
        # load firewall rules
        self.load_firewall_rules()
        
        # start shadow switch
        self.shadow = CCSShadowSwitch(self.host, self.port + 1)
        self.shadow.daemon = True

    # parse firewall_rules.txt
    def load_firewall_rules(self):
        """Load firewall rules from existing file"""
        try:
            with open('firewall_rules.txt', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            rule = FirewallRule.from_string(line)
                            if rule.network > 0:  # Only add valid rules
                                self.firewall_rules.append(rule)
                                print(f"Loaded firewall rule: {rule}")
                        except Exception as e:
                            print(f"Warning: Skipping invalid firewall rule '{line}': {e}")
                            
        except FileNotFoundError:
            print("Error: No firewall rules file found. Please create firewall_rules.txt")
            sys.exit(1)
        except Exception as e:
            print(f"Error loading firewall rules: {e}")
            sys.exit(1)


    def run(self):
        print(f"CCS running on {self.host}:{self.port}")
        
        # start shadow (just in case)
        self.shadow.start()
        
        while self.running:
            try:
                self.server_socket.settimeout(1.0) # timeout
                try:
                    conn, addr = self.server_socket.accept()
                    print(f"CCS: New connection from {addr}")
                    self.active_connections.add(conn)
                    handler = threading.Thread(target=self.handle_cas, args=(conn, addr))
                    handler.daemon = True
                    handler.start()
                except socket.timeout:
                    continue
            except Exception as e:
                if self.running:
                    print(f"CCS accept error: {e}")
                    if not self.server_socket:
                        break

    def check_firewall(self, frame: Frame):
        # check rules
        for rule in self.firewall_rules:
            if rule.network == frame.dst_network:
                if rule.local_only and frame.src_network != frame.dst_network:
                    return False
                if rule.node == frame.dst_node:
                    return not rule.local_only
        return True

    def handle_cas(self, conn: socket.socket, addr: tuple):
        print(f"New CAS connection from {addr}")
        
        try:
            self.send_firewall_rules(conn)
            
            while self.running:
                try:
                    conn.settimeout(1.0)
                    
                    # read frame
                    header = conn.recv(6)
                    if not header or len(header) < 6:
                        print(f"Connection closed by CAS {addr}")
                        break
                    
                    frame = Frame.bytes_to_frames(header)
                    
                    # read frame data
                    if frame.size > 0:
                        data = conn.recv(frame.size)
                        if len(data) < frame.size:
                            print(f"Incomplete data from CAS {addr}")
                            break
                        frame.data = data
                    
                    with self.forwarding_lock:
                        self.forwarding_table[frame.src_network] = (conn, addr)
                    
                    self.handle_frame(frame, conn)
                    
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    print(f"Connection reset by CAS {addr}")
                    break
                except Exception as e:
                    print(f"Error handling CAS {addr}: {e}")
                    break
        finally:
            # cleanup to make sure it always runs
            print(f"Cleaning up CAS connection from {addr}")
            try:
                conn.close()
            except:
                pass
                
            try:
                with self.forwarding_lock:
                    for network, (connection, _) in list(self.forwarding_table.items()):
                        if connection == conn:
                            del self.forwarding_table[network]
            except:
                pass
                
            try:
                if conn in self.active_connections:
                    self.active_connections.remove(conn)
            except:
                pass


    def send_firewall_rules(self, conn: socket.socket):
        # convert to string format
        rules_data = "\n".join([str(rule) for rule in self.firewall_rules])
        frame = Frame(
            src_network=0,
            src_node=0,
            dst_network=0,
            dst_node=0,
            frame_type=FrameType.FIREWALL_RULES,
            size=len(rules_data),
            data=rules_data.encode()
        )
        conn.sendall(frame.frame_to_bytes())

    def handle_frame(self, frame: Frame, sender_conn: socket.socket):
        with self.buffer_lock:
            self.frame_buffer.append(frame)
        
        # Check firewall rules
        if not self.check_firewall(frame):
            nack = Frame(
                src_network=0,
                src_node=0,
                dst_network=frame.src_network,
                dst_node=frame.src_node,
                frame_type=FrameType.NACK,
                size=0
            )
            try:
                sender_conn.sendall(nack.frame_to_bytes())
            except Exception as e:
                print(f"Error sending NACK: {e}")
            return
        
        with self.forwarding_lock:
            dest_conn = self.forwarding_table.get(frame.dst_network)
            
            if dest_conn:
                try:
                    dest_conn[0].sendall(frame.frame_to_bytes())
                except Exception as e:
                    print(f"Error forwarding to network {frame.dst_network}: {e}")
            else:
                # flood to all except sender
                for network, (conn, _) in self.forwarding_table.items():
                    if conn != sender_conn:
                        try:
                            conn.sendall(frame.frame_to_bytes())
                        except Exception as e:
                            print(f"Error flooding to network {network}: {e}")

    def shutdown(self):
        print("CCS: Initiating shutdown...")
        self.running = False
        
        # close connections
        for conn in self.active_connections.copy():
            try:
                conn.close()
            except:
                pass
        self.active_connections.clear()
        
        # close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        # close shadow switch
        if hasattr(self, 'shadow') and self.shadow:
            try:
                self.shadow.shutdown()
            except:
                pass
        
        print("CCS: Shutdown complete")

class CASSwitch(threading.Thread):
    
    def __init__(self, network_id: int, ccs_host: str = 'localhost', ccs_port: int = 5000, 
                 host: str = 'localhost', start_port: int = 6000):
        super().__init__()
        self.network_id = network_id
        self.host = host
        self.port = start_port + network_id
        self.running = True
        
        self.frame_buffer: List[Frame] = []
        self.buffer_lock = threading.Lock()
        self.switching_table: Dict[int, tuple] = {}
        self.switching_lock = threading.Lock()
        self.firewall_rules: List[FirewallRule] = []
        self.rules_lock = threading.Lock()
        
        self.ccs_host = ccs_host
        self.ccs_port = ccs_port
        self.ccs_socket = None
        self.ccs_connected = False
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(16)
        
        self.active_connections = set()
        
    def connect_to_ccs(self):
        """Establish connection to CCS with failover to shadow"""
        while self.running and not self.ccs_connected:
            try:
                self.ccs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.ccs_socket.connect((self.ccs_host, self.ccs_port))
                self.ccs_connected = True
                print(f"Network {self.network_id} connected to CCS")
                
                ccs_handler = threading.Thread(target=self.handle_ccs_messages)
                ccs_handler.daemon = True
                ccs_handler.start()
                
            except ConnectionRefusedError:
                print(f"Network {self.network_id}: Main CCS not available, trying shadow...")
                try:
                    self.ccs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.ccs_socket.connect((self.ccs_host, self.ccs_port + 1))
                    self.ccs_connected = True
                    print(f"Network {self.network_id} connected to Shadow CCS")
                    
                    ccs_handler = threading.Thread(target=self.handle_ccs_messages)
                    ccs_handler.daemon = True
                    ccs_handler.start()
                    
                except:
                    print(f"Network {self.network_id}: No CCS available, retrying in 1 second...")
                    time.sleep(1)
    
    def run(self):
        self.connect_to_ccs()
        
        print(f"CAS {self.network_id} listening for nodes on {self.host}:{self.port}")
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                try:
                    conn, addr = self.server_socket.accept()
                    self.active_connections.add(conn)
                    handler = threading.Thread(target=self.handle_node, args=(conn, addr))
                    handler.daemon = True
                    handler.start()
                except socket.timeout:
                    continue
            except Exception as e:
                if self.running:
                    print(f"CAS {self.network_id} accept error: {e}")
    
    def handle_ccs_messages(self):
        while self.running and self.ccs_connected:
            try:
                header = self.ccs_socket.recv(6)
                if not header or len(header) < 6:
                    break
                
                frame = Frame.bytes_to_frames(header)
                
                if frame.size > 0:
                    data = self.ccs_socket.recv(frame.size)
                    if len(data) < frame.size:
                        break
                    frame.data = data
                
                if frame.frame_type == FrameType.FIREWALL_RULES:
                    rules_str = frame.data.decode()
                    with self.rules_lock:
                        self.firewall_rules = [FirewallRule.from_string(rule) for rule in rules_str.split('\n')]
                else:
                    self.handle_frame_from_ccs(frame)
                    
            except Exception as e:
                print(f"CAS {self.network_id} lost connection to CCS: {e}")
                self.ccs_connected = False
                break
        # try reconnect
        self.connect_to_ccs()
    
    def check_local_firewall(self, frame: Frame):
        with self.rules_lock:
            for rule in self.firewall_rules:
                if rule.network == self.network_id:
                    if rule.node == frame.dst_node and rule.local_only:
                        return frame.src_network == self.network_id
        return True
    
    def handle_node(self, conn: socket.socket, addr: tuple):
        print(f"New node connection from {addr} in network {self.network_id}")
        
        try:
            while self.running:
                try:
                    conn.settimeout(1.0)
                    
                    header = conn.recv(6)
                    if not header or len(header) < 6:
                        print(f"Connection closed by node at {addr}")
                        break
                        
                    frame = Frame.bytes_to_frames(header)
                    
                    if frame.size > 0:
                        data = conn.recv(frame.size)
                        if len(data) < frame.size:
                            print(f"Incomplete data from node at {addr}")
                            break
                        frame.data = data
                    
                    with self.switching_lock:
                        self.switching_table[frame.src_node] = (conn, addr)
                    
                    # handle frame
                    self.handle_frame_from_node(frame, conn)
                    
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    print(f"Connection reset by node at {addr}")
                    break
                except Exception as e:
                    print(f"Error handling node in network {self.network_id}: {e}")
                    break
        finally:
            print(f"Cleaning up node connection from {addr}")
            try:
                conn.close()
            except:
                pass
                
            try:
                if conn in self.active_connections:
                    self.active_connections.remove(conn)
            except:
                pass
                
            try:
                with self.switching_lock:
                    # Clean switching table
                    for node_id, (connection, _) in list(self.switching_table.items()):
                        if connection == conn:
                            del self.switching_table[node_id]
            except:
                pass
    
    def handle_frame_from_node(self, frame: Frame, sender_conn: socket.socket):
        with self.buffer_lock:
            self.frame_buffer.append(frame)
        
        if frame.dst_network == self.network_id:
            if not self.check_local_firewall(frame):
                nack = Frame(
                    src_network=self.network_id,
                    src_node=0,  # CAS
                    dst_network=frame.src_network,
                    dst_node=frame.src_node,
                    frame_type=FrameType.NACK,
                    size=0
                )
                try:
                    sender_conn.sendall(nack.frame_to_bytes())
                except Exception as e:
                    print(f"Error sending NACK: {e}")
                return
            
            with self.switching_lock:
                dest_conn = self.switching_table.get(frame.dst_node)
                if dest_conn:
                    try:
                        dest_conn[0].sendall(frame.frame_to_bytes())
                    except Exception as e:
                        print(f"Error sending to local node {frame.dst_node}: {e}")
                else:
                    for node_id, (conn, _) in self.switching_table.items():
                        if conn != sender_conn:
                            try:
                                conn.sendall(frame.frame_to_bytes())
                            except Exception as e:
                                print(f"Error flooding to local node {node_id}: {e}")
        else:
            if self.ccs_connected:
                try:
                    self.ccs_socket.sendall(frame.frame_to_bytes())
                except Exception as e:
                    print(f"Error forwarding to CCS: {e}")
                    self.ccs_connected = False
                    self.connect_to_ccs()
    
    def handle_frame_from_ccs(self, frame: Frame):
        if frame.dst_network != self.network_id:
            return
            
        with self.switching_lock:
            dest_conn = self.switching_table.get(frame.dst_node)
            if dest_conn:
                try:
                    dest_conn[0].sendall(frame.frame_to_bytes())
                except Exception as e:
                    print(f"Error forwarding CCS frame to node {frame.dst_node}: {e}")
    
    def shutdown(self):
        print(f"CAS {self.network_id}: Initiating shutdown...")
        self.running = False
        
        if self.ccs_socket:
            try:
                self.ccs_socket.close()
            except:
                pass
            
        for conn in self.active_connections.copy():
            try:
                conn.close()
            except:
                pass
                
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
                
        print(f"CAS {self.network_id}: Shutdown complete")


class Node(threading.Thread):
    
    def __init__(self, network_id: int, node_id: int, cas_host: str = 'localhost', start_port: int = 6000):
        super().__init__()
        self.network_id = network_id
        self.node_id = node_id
        self.cas_host = cas_host
        self.cas_port = start_port + network_id
        self.running = True
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.received_data = []
        self.frame_buffer: Dict[bytes, Frame] = {}  # Buffer for unacknowledged frames
        
        self.input_file = f"node{network_id}_{node_id}.txt"
        self.output_file = f"node{network_id}_{node_id}output.txt"
        
        self.data_sent = threading.Event()
        self.max_retries = 3
    
    def run(self):
        while self.running:
            try:
                self.socket.connect((self.cas_host, self.cas_port))
                print(f"Node {self.network_id}_{self.node_id} connected to CAS")
                break
            except ConnectionRefusedError:
                print(f"Node {self.network_id}_{self.node_id}: CAS not ready, retrying...")
                time.sleep(1)
        
        if not self.running:
            return
        
        receiver = threading.Thread(target=self.receive_data)
        receiver.daemon = True
        receiver.start()
        
        # process input file
        self.process_input_file()
        self.data_sent.set()
        
        self.handle_retransmissions()
        
        # cleanup
        self.shutdown()
    
    def receive_data(self):
        self.socket.settimeout(1.0)
        
        while self.running:
            try:
                header = self.socket.recv(6)
                if not header or len(header) < 6:
                    break
                
                frame = Frame.bytes_to_frames(header)
                
                if frame.size > 0:
                    data = self.socket.recv(frame.size)
                    if len(data) < frame.size:
                        break
                    frame.data = data
                
                if frame.frame_type == FrameType.DATA and frame.dst_node == self.node_id:
                    # random frame errors (5% chance)
                    if random.random() < 0.05:
                        print(f"Node {self.network_id}_{self.node_id}: Simulated frame error")
                        continue
                    
                    self.received_data.append(
                        f"{frame.src_network}_{frame.src_node}: {frame.data.decode()}"
                    )
                    
                    # random ACK failure (5% chance)
                    if random.random() < 0.05:
                        print(f"Node {self.network_id}_{self.node_id}: Simulated ACK failure")
                        continue
                    
                    ack = Frame(
                        src_network=self.network_id,
                        src_node=self.node_id,
                        dst_network=frame.src_network,
                        dst_node=frame.src_node,
                        frame_type=FrameType.ACK,
                        size=0
                    )
                    self.socket.sendall(ack.frame_to_bytes())
                    
                elif frame.frame_type == FrameType.ACK:
                    key = f"{frame.src_network}_{frame.src_node}".encode()
                    self.frame_buffer.pop(key, None)
                    
                elif frame.frame_type == FrameType.NACK:
                    print(f"Node {self.network_id}_{self.node_id}: Received NACK, will retransmit")
                    
            except socket.timeout:
                if self.data_sent.is_set() and not self.frame_buffer:
                    break
            except Exception as e:
                if self.running:
                    print(f"Node {self.network_id}_{self.node_id} receive error: {e}")
                break
    
    def process_input_file(self):
        try:
            with open(f"in/{self.input_file}", 'r') as f:
                print(f"Node {self.network_id}_{self.node_id}: Processing input file")
                for line in f:
                    if not line.strip():
                        continue
                    
                    dest, data = line.strip().split(':', 1)
                    dest_network, dest_node = map(int, dest.split('_'))
                    data = data.strip().encode()
                    
                    print(f"Node {self.network_id}_{self.node_id}: Sending to {dest_network}_{dest_node}: {data.decode()}")
                    
                    # create frame
                    frame = Frame(
                        src_network=self.network_id,
                        src_node=self.node_id,
                        dst_network=dest_network,
                        dst_node=dest_node,
                        frame_type=FrameType.DATA,
                        size=len(data),
                        data=data
                    )
                    
                    buffer_key = f"{dest_network}_{dest_node}".encode()
                    self.frame_buffer[buffer_key] = frame
                    
                    # send frame
                    self.socket.sendall(frame.frame_to_bytes())
                    
                    # wait
                    time.sleep(0.1)
                    
        except FileNotFoundError:
            print(f"Node {self.network_id}_{self.node_id}: Input file not found")
    
    def handle_retransmissions(self):
        retries = {k: 0 for k in self.frame_buffer.keys()}
        
        while self.running and self.frame_buffer:
            for key, frame in list(self.frame_buffer.items()):
                if retries[key] >= self.max_retries:
                    print(f"Node {self.network_id}_{self.node_id}: Max retries reached for frame to {frame.dst_network}_{frame.dst_node}")
                    self.frame_buffer.pop(key)
                    retries.pop(key)
                    continue
                
                try:
                    self.socket.sendall(frame.frame_to_bytes())
                    retries[key] += 1
                except Exception as e:
                    print(f"Node {self.network_id}_{self.node_id} retransmission error: {e}")
                    break
            
            time.sleep(1) # wait
    
    def save_output(self):
        os.makedirs("out", exist_ok=True)
        with open(f"out/{self.output_file}", 'w') as f:
            for line in self.received_data:
                f.write(line + '\n')
    
    def shutdown(self):
        print(f"Node {self.network_id}_{self.node_id}: Initiating shutdown...")
        self.running = False
        self.save_output()
        self.socket.close()
        print(f"Node {self.network_id}_{self.node_id}: Shutdown complete")


def main():
    if len(sys.argv) != 3:
        print("Usage: python star_of_stars.py <number_of_networks> <nodes_per_network>")
        sys.exit(1)
    
    try:
        num_networks = int(sys.argv[1])
        nodes_per_network = int(sys.argv[2])
        
        if not (2 <= num_networks <= 16):
            raise ValueError("Number of networks must be between 2 and 16")
        if not (2 <= nodes_per_network <= 16):
            raise ValueError("Number of nodes per network must be between 2 and 16")
            
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # create directories if not exist already
    os.makedirs("in", exist_ok=True)
    os.makedirs("out", exist_ok=True)

    # generate input files
    print("Generating in files...")
    generate_in_files(num_networks, nodes_per_network)

    # start CCS and shadow
    print("Starting Central Core Switch...")
    ccs = None
    try:
        ccs = CCSSwitch()
        ccs.daemon = True
        ccs.start()
        
        # wait for CCS
        time.sleep(2)
        
        # start CAS
        print("Starting Core AS Switches...")
        cas_switches = []
        for network_id in range(1, num_networks + 1):
            cas = CASSwitch(network_id)
            cas_switches.append(cas)
            cas.start()
        
        # wait for CAS
        time.sleep(2)
        
        # start nodes
        print("Creating and starting nodes...")
        nodes = []
        for network_id in range(1, num_networks + 1):
            for node_id in range(1, nodes_per_network + 1):
                node = Node(network_id, node_id)
                nodes.append(node)
                node.start()
        
        # wait for nodes to complete
        print("Waiting for nodes to complete...")
        try:
            for node in nodes:
                node.join(timeout=30)
        except TimeoutError:
            print("Timeout waiting for nodes to complete")
        
        # cleanup
        print("Shutting down nodes...")
        for node in nodes:
            node.shutdown()
            
        print("Shutting down CAS switches...")
        for cas in cas_switches:
            cas.shutdown()
            
    except Exception as e:
        print(f"Error in main: {e}")
    finally:
        if ccs:
            print("Shutting down CCS...")
            ccs.shutdown()
        
    print("Done!")

if __name__ =='__main__':
    main()