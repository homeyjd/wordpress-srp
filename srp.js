/*
The Secure Remote Password protocol (SRP) is a secure password-based authentication and key-exchange protocol. It solves the problem of authenticating clients to servers securely, in cases where the user of the client software must memorize a small secret (like a password or a passphrase) and where the server carries a verifier for each user, which allows it to authenticate the client but which, if compromised, would not allow the attacker to impersonate the client. In addition, SRP exchanges a cryptographically-strong secret as a byproduct of successful authentication, which enables the two parties to communicate securely.

SRP offers a number of new benefits for password system implementors:

An attacker with neither the user’s password nor the host’s password file cannot mount a dictionary attack on the password.
An attacker who captures the host’s password file cannot directly compromise user-to-host authentication and gain access to the host without an expensive dictionary search.
An attacker who compromises the host does not obtain the the password from a legitimate authentication attempt.
An attacker who captures the session key cannot use it to mount a dictionary attack on the password.
It is believed that this set of properties is at or near the theoretical limit of security that can be offered by a purely password-based protocol. SRP, which bases its security on the difficulty of solving the Diffie-Hellman problem in the multiplicative field modulo a large safe prime, meets these requirements and does so using only one exponential key exchange round, making it useful for applications in which good performance is an issue. SRP’s security, simplicity, and speed make it ideal for a wide range of real-world applications in which secure password authentication is required. Further technical details of the actual protocol design are available from the Stanford SRP Authentication Project website.

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

*/

function depends(url) {
	var tag 	= document.createElement("script");
	tag.type 	= "text/javascript";
	tag.src 	= url;
	var s = document.getElementsByTagName('script')[0];
	s.parentNode.insertBefore(ga, s);
}

// CryptoJS Library @ http://code.google.com/p/crypto-js/
depends('http://crypto-js.googlecode.com/svn/tags/3.1.2/build/rollups/sha256.js');
// Clipperz
depends('Clipperz/ByteArray.js');
depends('Clipperz/Crypto/BigInt.js');
depends('Clipperz/Crypto/PRNG.js');

if (typeof(SRP) == 'undefined') { SRP = {}; }

SRP.Session = function (sessid, username, password, postURL, callback, errCallback) {
	var 
		conn = new SRP.Connection({
				username: username,
				password: password,
				hash: CryptoJS.SHA256
		})
		, req = function(data, success) {
			$.ajax({
				url: postURL,
				type: 'POST',
				cache: false,
				data: data,
				dataType: 'json',
				success: success,
				error: err
			});
		}
		, err = function(text, textStatus, errorThrown) {
			if (typeof text !== 'string' && errorThrown) {
				text = errorThrown;
			}
			if (console && console.log) {
				console.log("SRP Error: "+text);
			}
			if (errCallback) {
				errCollback.call(text);
			}
			return false;
		}
		, step1 = function() {
			req({'username':username}, step2);
		}
		, step2 = function(result) {
			if (!result) {
				return err( "SRP: improper response" );
			}
			//conn.x(); implicit
			conn._s = result.s;
			
			req({'A':conn.A()}, step3);
		}
		, step3 = function(result) {
			if (!result) {
				return err( "SRP: improper response" );
			}
			conn._B = result.B;
			//conn.u(); implicit
			//conn.S(); implicit
			req({'M1':conn.M1()}, step4);
		}
		, step4 = function(result) {
			if (!result) {
				return err( "SRP: improper response" );
			}
			if (conn.M2() == result.M2) {
				if (typeof callback === 'function') callback.call(conn.K());
			} else {
				return err( 'SRP: M2 Verifiers did not match' );
			}
		}
		;
};


SRP = {

	'init': function(args) {
		for(var k in args) {
			SRP[k] = args[k];
		}
	},
	
	//-------------------------------------------------------------------------
	
	'_n': null,
	'_g': null,

	//-------------------------------------------------------------------------

	'n': function() {
		if (SRP._n == null) {
		 	SRP._n = new Clipperz.Crypto.BigInt("115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3", 16);
		}
		
		return SRP._n;
	},

	//-------------------------------------------------------------------------

	'g': function() {
		if (SRP._g == null) {
			SRP._g = new Clipperz.Crypto.BigInt(2);	//	eventually 5 (as suggested on the Diffi-Helmann documentation)
		}
		
		return SRP._g;
	},
	
	'hash': function(input) {
		throw 'Requires a hash function.';
	}
};

SRP.Connection = function (args) {
	args = args || {};

	this._C = args.username;
	this._P = args.password;
	this.hash = args.hash;

	this._a = null;
	this._A = null;
	
	this._s = null;
	this._B = null;

	this._x = null;
	
	this._u = null;
	this._K = null;
	this._M1 = null;
	this._M2 = null;
	
	this._sessionKey = null;

	return this;
};

SRP.Connection.prototype = {

	//-------------------------------------------------------------------------

	'a': function () {
		if (this._a == null) {
			this._a = new Clipperz.Crypto.BigInt(Clipperz.Crypto.PRNG.defaultRandomGenerator().getRandomBytes(32).toHexString().substring(2), 16);
		}
		
		return this._a;
	},

	//-------------------------------------------------------------------------

	'A': function () {
		if (this._A == null) {
			//	Warning: this value should be strictly greater than zero: how should we perform this check?
			this._A = SRP.g().powerModule(this.a(), SRP.n());
			
			if (this._A.equals(0)) {
//MochiKit.Logging.logError("Clipperz.Crypto.SRP.Connection: trying to set 'A' to 0.");
				throw "SRP: invalid value";
			}
//MochiKit.Logging.logDebug("SRP A: " + this._A);
		}
		
		return this._A;
	},

	//-------------------------------------------------------------------------

	's': function () {
		return this._s;
//MochiKit.Logging.logDebug("SRP s: " + this._S);
	},

	'set_s': function(aValue) {
		this._s = aValue;
	},
	
	//-------------------------------------------------------------------------

	'B': function () {
		return this._B;
	},

	'set_B': function(aValue) {
		//	Warning: this value should be strictly greater than zero: how should we perform this check?
		if (! aValue.equals(0)) {
			this._B = aValue;
//MochiKit.Logging.logDebug("SRP B: " + this._B);
		} else {
//MochiKit.Logging.logError("Clipperz.Crypto.SRP.Connection: trying to set 'B' to 0.");
			throw "SRP: invalid value";
		}
	},
	
	//-------------------------------------------------------------------------

	'x': function () {
		if (this._x == null) {
			this._x = new Clipperz.Crypto.BigInt(this.stringHash(this.s().asString(16, 64) + this.P()), 16);
//MochiKit.Logging.logDebug("SRP x: " + this._x);
		}
		
		return this._x;
	},

	//-------------------------------------------------------------------------

	'u': function () {
		if (this._u == null) {
			this._u = new Clipperz.Crypto.BigInt(this.stringHash(this.B().asString()), 16);
//MochiKit.Logging.logDebug("SRP u: " + this._u);
		}
		
		return this._u;
	},

	//-------------------------------------------------------------------------

	'S': function () {
		if (this._S == null) {
			var bigint;
			var	srp;

			bigint = Clipperz.Crypto.BigInt;
			srp = 	 Clipperz.Crypto.SRP;

			this._S =	bigint.powerModule(
								bigint.subtract(this.B(), bigint.powerModule(srp.g(), this.x(), srp.n())),
								bigint.add(this.a(), bigint.multiply(this.u(), this.x())),
								srp.n()
						)
//MochiKit.Logging.logDebug("SRP S: " + this._S);
		}
		
		return this._S;
	},

	//-------------------------------------------------------------------------

	'K': function () {
		if (this._K == null) {
			this._K = this.stringHash(this.S().asString());
//MochiKit.Logging.logDebug("SRP K: " + this._K);
		}
		
		return this._K;
	},

	//-------------------------------------------------------------------------

	'M1': function () {
		if (this._M1 == null) {
			this._M1 = this.stringHash(this.A().asString(10) + this.B().asString(10) + this.K());
//MochiKit.Logging.logDebug("SRP M1: " + this._M1);
		}
		
		return this._M1;
	},

	//-------------------------------------------------------------------------

	'M2': function () {
		if (this._M2 == null) {
			this._M2 = this.stringHash(this.A().asString(10) + this.M1() + this.K());
//MochiKit.Logging.logDebug("SRP M2: " + this._M2);
		}
		
		return this._M2;
	},

	//=========================================================================

	'serverSideCredentialsWithSalt': function(aSalt) {
		var result;
		var s, x, v;
		
		s = aSalt;
		x = this.stringHash(s + this.P());
		v = SRP.g().powerModule(new Clipperz.Crypto.BigInt(x, 16), SRP.n());

		result = {};
		result['C'] = this.C();
		result['s'] = s;
		result['v'] = v.asString(16);
		
		return result;
	},
	
	'serverSideCredentials': function() {
		var result;
		var s;
		
		s = Clipperz.Crypto.PRNG.defaultRandomGenerator().getRandomBytes(32).toHexString().substring(2);

		result = this.serverSideCredentialsWithSalt(s);
		
		return result;
	},
	
	//=========================================================================
/*
	'computeServerSide_S': function(b) {
		var result;
		var v;
		var bigint;
		var	srp;

		bigint = Clipperz.Crypto.BigInt;
		srp = 	 Clipperz.Crypto.SRP;

		v = new Clipperz.Crypto.BigInt(srpConnection.serverSideCredentialsWithSalt(this.s().asString(16, 64)).v, 16);
//		_S =  (this.A().multiply(this.v().modPow(this.u(), this.n()))).modPow(this.b(), this.n());
		result = bigint.powerModule(
					bigint.multiply(
						this.A(),
						bigint.powerModule(v, this.u(), srp.n())
					), new Clipperz.Crypto.BigInt(b, 10), srp.n()
				);

		return result;
	},
*/
	//=========================================================================

	'stringHash': function(aValue) {
		var	result;

		result = this.hash(new Clipperz.ByteArray(aValue)).toHexString().substring(2);
		
		return result;
	},
	
	__: ''
};