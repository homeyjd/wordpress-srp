<?php
/**
 * A class for tracking an SRP authentication process.
 *
Inputs:
	I - The user’s identifier or username
	P - The user’s password
Pre-defined Constants:
	g - A primitive root modulo n (often called a generator)
	n - A large prime number
	Hash( ) - One-way hash function
Stored-once Inputs:
	s - A random string generated once, stored, and used as the user’s salt
	v - The host’s password verifier
Derived Variables:
	x - A private key derived from the password and salt
	u - Random scrambling parameter, publicly revealed
	a, b - Ephemeral private keys, generated randomly and not publicly revealed
	A, B - Corresponding public keys
	K - Session key


Step 1: 
	Client sends user identifier/username to the server
	Server lookup s, v, respond s
Step 2:
	Client x = Hash(s, I, P)
	Client A = g^a
Step 3:
	Client sends A
	Server B = 3v + g^b, u = Hash(A,B), responds with B
	Client u = Hash(A,B)
Step 4:
	Client S = (B - 3(g^x))^(u*x+a)
	Server S = (A(v^u)^b
Step 5:
	Client M1 = Hash(A,B,S), sends M1
	Server verify M1 with Hash(A,B,S)
	Server M2 = H(A,M1,S), respond M2
Step 6:
	Client verify M2 = Hash(A,M1,S)
	Client K = Hash(S)
	Server K = Hash(S)
**/

abstract class SRP_Session {
	public var $_n, $_g, $hash = 'sha1'; // static
		
	// per session
	protected var $username;
	protected var $_s, $_v;
	
	// 
	private var $_A, $_b, $_B;
	// derived
	private var $_x, $_u, $_K, $_M1, $_M2;
	
	public function SRP_Session($username=null) {
		if ($username !== null) {
			$this->username = $username;
			$this->lookup_user_salt();
		}
	}
	
	public function user_salt() {
		if ($this->_s === null) {
			$this->lookup_user_salt();
		}
		return $this->_s;
	}
	
	public function B($A=null) {
		$this->_A = $A;
		$this->_B = (3 * $this->_v) + pow($this->_g, $this->_b());
		$this->_u = call_user_func_array($this->hash, array( $this->_A . $this->_B ));
		
		return $this->_B;
	}
	
	public function M1($M1) {
		$this->M1 = $M1;
		$M2 = call_user_func_array($this->hash, array( $this->_A . $this->_B . $this->_S()));
		if ($M2 !== $M1) {
			throw new Exception('SRP: The provided M1 does not match');
		}
		
		$this->M2 = call_user_func_array($this->hash, array( $this->_A . $M1 . $this->_S() ));
		
		return $this->M2;
	}
	
	public function K() {
		return call_user_func_array($this->hash, array( $this->_S() );
	}
	
	
	
	private function _b() {
		if ($this->_b === null) {
			$this->_b = new Clipperz.Crypto.BigInt(Clipperz.Crypto.PRNG.defaultRandomGenerator().getRandomBytes(32).toHexString().substring(2), 16);
		}
		return $this->_b;
	}
	
	private function _S() {
		if ($this->_S === null) {
			$this->_S = pow($this->_A * pow($this->_v, $this->_u), $this->_b);
		}
		return $this->_S;
	}
	
	/**
	 * Must populate $_s (per-used salt value) and $_v (server-side password verifier.
	 **/
	abstract protected function lookup_user_salt();
	
}//class


class SRP_WordPress_Session extends SRP_Session {
	protected function lookup_user_salt() {
		$logged_in = wp_get_current_user();
		if ($logged_in) {
			// use current logged in user
		} else {
			// use $this->username
		}
		// query meta for srp_salt and srp_verifier
		// save to $this->_s and _v
	}
}