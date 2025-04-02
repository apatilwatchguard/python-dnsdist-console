import socket
import libnacl
import libnacl.utils
import struct
import base64
import time
import logging
from typing import Optional, Union, Tuple

# Setup logger
logger = logging.getLogger("improved-dnsdist-console")

class ConsoleError(Exception):
    """Base class for Console exceptions"""
    pass

class ConnectionError(ConsoleError):
    """Connection related exceptions"""
    pass

class AuthenticationError(ConsoleError):
    """Authentication related exceptions"""
    pass

class CommandError(ConsoleError):
    """Command related exceptions"""
    pass

class TimeoutError(ConsoleError):
    """Timeout related exceptions"""
    pass

def is_ipv4_address(address):
    """Check if the address is an IPv4 address"""
    try:
        socket.inet_pton(socket.AF_INET, address)
        return True
    except (socket.error, TypeError):
        return False

class Console:
    def __init__(self, key, host="127.0.0.1", port=5199, timeout=5.0, max_retries=3, retry_delay=1.0):
        """
        DNSDist Console client with improved connection handling
        
        Args:
            key (str): Base64 encoded console key
            host (str): Console host address
            port (int): Console port
            timeout (float): Socket timeout in seconds
            max_retries (int): Maximum number of connection retry attempts
            retry_delay (float): Delay between retry attempts in seconds
        """
        self.console_host = host
        self.console_port = port
        self.console_key = base64.b64decode(key) if isinstance(key, str) else key
        
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.sock_timeout = timeout
        
        self.nonce_c = None
        self.nonce_s = None
        self.nonce_w = None
        self.nonce_r = None
        self.sock = None
        
        # Connect with retries
        self._connect_with_retries()
    
    def _connect_with_retries(self):
        """Attempt to connect with retries"""
        last_exception = None
        
        for attempt in range(1, self.max_retries + 1):
            try:
                self._initialize_connection()
                return  # Successfully connected
            except ConsoleError as e:
                last_exception = e
                logger.warning(f"Connection attempt {attempt}/{self.max_retries} failed: {e}")
                
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
        
        # If we get here, all retries failed
        raise ConnectionError(f"Failed to connect after {self.max_retries} attempts: {last_exception}")
    
    def _initialize_connection(self):
        """Initialize connection and perform handshake"""
        # Initialize nonces
        self.nonce_c = libnacl.utils.rand_nonce()
        
        # Create and configure socket
        if is_ipv4_address(self.console_host):
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(self.sock_timeout)
        
        try:
            # Connect to server
            self.sock.connect((self.console_host, self.console_port))
            
            # Send client nonce
            self.sock.send(self.nonce_c)
            
            # Receive server nonce
            self.nonce_s = self.sock.recv(len(self.nonce_c))
            if len(self.nonce_s) != len(self.nonce_c):
                raise AuthenticationError("Incorrect nonce size received from server")
            
            # Initialize reading and writing nonces
            half_nonce = int(len(self.nonce_c) / 2)
            self.nonce_r = self.nonce_c[0:half_nonce] + self.nonce_s[half_nonce:]
            self.nonce_w = self.nonce_s[0:half_nonce] + self.nonce_c[half_nonce:]
            
            # Verify handshake with empty command
            try:
                self._send_command_internal("")
                logger.debug("Successfully connected to console")
            except Exception as e:
                raise AuthenticationError(f"Handshake failed: {e}")
                
        except socket.timeout:
            self.disconnect()
            raise TimeoutError("Connection timed out")
        except socket.error as e:
            self.disconnect()
            raise ConnectionError(f"Socket error: {e}")
        except Exception as e:
            self.disconnect()
            raise ConsoleError(f"Unexpected error during connection: {e}")
    
    def encrypt_command(self, cmd, nonce):
        """Encrypt console command"""
        cmd = cmd.encode('utf-8') if isinstance(cmd, str) else cmd
        return libnacl.crypto_secretbox(cmd, nonce, self.console_key)
    
    def decrypt_response(self, data, nonce):
        """Decrypt console response"""
        result = libnacl.crypto_secretbox_open(data, nonce, self.console_key)
        return result.decode('utf-8')
    
    def increment_nonce(self, nonce):
        """Increment nonce"""
        v = int.from_bytes(nonce[:4], "big")
        v += 1
        return v.to_bytes(4, byteorder='big') + nonce[4:]
    
    def disconnect(self):
        """Disconnect from console"""
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception as e:
                logger.warning(f"Error during disconnect: {e}")
            finally:
                self.sock = None
    
    def is_connected(self):
        """Check if the connection is established"""
        if self.sock is None:
            return False
            
        try:
            # Try to get socket status
            self.sock.getpeername()
            return True
        except Exception:
            return False
    
    def _send_command_internal(self, cmd):
        """Internal method to send command without retries"""
        if not self.is_connected():
            raise ConnectionError("Not connected to console")
            
        try:
            # Encrypt command
            encrypted_cmd = self.encrypt_command(cmd, self.nonce_w)
            
            # Send data size header
            self.sock.send(struct.pack("!I", len(encrypted_cmd)))
            
            # Send encrypted command
            self.sock.send(encrypted_cmd)
            
            # Receive response size
            data = self.sock.recv(4)
            if not data:
                raise ConnectionError("No response size received")
                
            # Unpack response size
            (response_size,) = struct.unpack("!I", data)
            
            # Receive response data
            data = bytearray()
            bytes_received = 0
            
            while bytes_received < response_size:
                chunk = self.sock.recv(min(4096, response_size - bytes_received))
                if not chunk:
                    raise ConnectionError("Connection closed while receiving data")
                    
                data.extend(chunk)
                bytes_received += len(chunk)
            
            # Decrypt response
            result = self.decrypt_response(data, self.nonce_r)
            
            # Increment nonces for next command
            self.nonce_r = self.increment_nonce(nonce=self.nonce_r)
            self.nonce_w = self.increment_nonce(nonce=self.nonce_w)
            
            return result
            
        except socket.timeout:
            raise TimeoutError("Command timed out")
        except socket.error as e:
            raise ConnectionError(f"Socket error: {e}")
        except ConsoleError:
            raise  # Re-raise console errors without wrapping
        except Exception as e:
            raise CommandError(f"Error executing command: {e}")
    
    def send_command(self, cmd, retries=None):
        """
        Send command to console with automatic reconnection
        
        Args:
            cmd (str): Command to send
            retries (int, optional): Number of retries, defaults to self.max_retries
            
        Returns:
            str: Command response
        """
        if retries is None:
            retries = self.max_retries
            
        last_error = None
        
        for attempt in range(1, retries + 1):
            try:
                # Check connection and reconnect if needed
                if not self.is_connected():
                    logger.debug("Connection lost, reconnecting...")
                    self._connect_with_retries()
                
                # Send command
                return self._send_command_internal(cmd)
                
            except (ConnectionError, TimeoutError) as e:
                last_error = e
                logger.warning(f"Command attempt {attempt}/{retries} failed: {e}")
                
                # Reconnect for the next attempt
                if attempt < retries:
                    self.disconnect()
                    time.sleep(self.retry_delay)
                    try:
                        self._connect_with_retries()
                    except ConsoleError as connect_error:
                        logger.warning(f"Reconnection failed: {connect_error}")
                        # Continue to next attempt
        
        # If we get here, all retries failed
        raise CommandError(f"Command failed after {retries} attempts: {last_error}")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()
    
    def __del__(self):
        """Destructor to ensure socket is closed"""
        self.disconnect()
