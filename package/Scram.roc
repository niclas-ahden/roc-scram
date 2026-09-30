import hmac.Hmac
import base64.Base64

## Client-side SCRAM-SHA-256 authentication (RFC 5802, RFC 7677), with
## channel binding for SCRAM-SHA-256-PLUS (`tls-server-end-point`, RFC 5929).
##
## The module is pure. You supply the client nonce and the channel binding
## data, and carry the messages over whatever protocol speaks SASL
## (PostgreSQL, MongoDB, Kafka, SMTP, IMAP):
##
## ```
## binding = Scram.select({
##     offered: ["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"],
##     transport: TlsWithEndPoint(end_point),
##     require_channel_binding: Bool.True,
## })?
## first = Scram.start({ username: "", password, nonce, channel_binding: binding })?
## send!(first.mechanism(), first.message())?
## final = first.receive_server_first(receive!()?)?
## send!(final.message())?
## final.verify_server_final(receive!()?)?
## ```
##
## `end_point` is the `tls-server-end-point` value of the TLS connection,
## which the platform has to provide. Over plain TCP the transport is
## `Plain` and the mechanism SCRAM-SHA-256.
##
## Only trust the server once [Scram.ClientFinal.verify_server_final]
## succeeded. That check is what proves the server knows the password too,
## so a server that reports success before it must be refused.
##
## The nonce must come from a cryptographically secure source, the
## operating system's (basic-cli's `Random.seed_u64!` is one: three calls
## give 24 bytes). It needs at least 18 bytes, which is what libpq sends.
##
## The username and the password are used as their UTF-8 bytes. SASLprep
## (RFC 4013) is not applied, which makes no difference for ASCII. A
## password that SASLprep would change (unnormalized Unicode, non-ASCII
## spaces, soft hyphens) fails to authenticate against a server that
## normalized it when it stored the password, as PostgreSQL does. Such a
## username may not be found by a server that expects it prepared.
## PostgreSQL ignores the SCRAM username, so there only the password matters.
Scram :: [].{

	## How the client binds the authentication to the connection underneath,
	## which becomes the GS2 header of RFC 5802:
	##
	## - `Unsupported` (`n`): no channel binding on this connection.
	## - `ServerLacksPlus` (`y`): the client could bind, but the server did not
	##   offer SCRAM-SHA-256-PLUS. A server that did offer it, and had the offer
	##   stripped by someone in between, notices and refuses.
	## - `TlsServerEndPoint(bytes)` (`p=tls-server-end-point`): bind to the TLS
	##   connection, with the `tls-server-end-point` value of RFC 5929.
	##
	## [Scram.select] picks one from what the server offered.
	ChannelBinding : [Unsupported, ServerLacksPlus, TlsServerEndPoint(List(U8))]

	## The mechanism without channel binding, as a server lists it.
	mechanism : Str
	mechanism = "SCRAM-SHA-256"

	## The mechanism with channel binding, as a server lists it.
	mechanism_plus : Str
	mechanism_plus = "SCRAM-SHA-256-PLUS"

	## Pick the channel binding from the mechanisms the server offered and the
	## connection underneath:
	##
	## - `Plain`: plain TCP, so no binding is possible.
	## - `Tls`: TLS without an end point value, as with an Ed25519 server
	##   certificate, which has none.
	## - `TlsWithEndPoint(bytes)`: TLS with its `tls-server-end-point` value.
	##
	## With `require_channel_binding`, anything but SCRAM-SHA-256-PLUS over TLS
	## fails: `ChannelBindingRequired` when the server did not offer PLUS, and
	## `ChannelBindingUnavailable` when the connection cannot be bound. Over
	## TLS without the requirement, a server that does not offer PLUS gets
	## `ServerLacksPlus`, so a PLUS offer stripped in transit is caught.
	## `ScramNotOffered` means neither SCRAM-SHA-256 mechanism was offered, or
	## only PLUS was and the connection cannot be bound.
	select : { offered : List(Str), transport : [Plain, Tls, TlsWithEndPoint(List(U8))], require_channel_binding : Bool } -> Try(Scram.ChannelBinding, [ScramNotOffered, ChannelBindingRequired, ChannelBindingUnavailable])
	select = |{ offered, transport, require_channel_binding }| {
		has_plus = offered.contains(Scram.mechanism_plus)
		has_plain = offered.contains(Scram.mechanism)
		if !has_plus and !has_plain {
			Err(ScramNotOffered)
		} else {
			match transport {
				TlsWithEndPoint(end_point) =>
					if has_plus {
						Ok(TlsServerEndPoint(end_point))
					} else if require_channel_binding {
						Err(ChannelBindingRequired)
					} else {
						Ok(ServerLacksPlus)
					}
				Tls | Plain =>
					if require_channel_binding {
						Err(ChannelBindingUnavailable)
					} else if has_plain {
						Ok(Unsupported)
					} else {
						Err(ScramNotOffered)
					}
			}
		}
	}

	## Begin an authentication. `nonce` is at least 18 random bytes, see the
	## module documentation. The username may be empty, as in PostgreSQL,
	## which takes it from the startup message instead. `=` and `,` in it are
	## escaped as RFC 5802 asks.
	##
	## `min_iterations` and `max_iterations` bound the iteration count the
	## server may ask for, 4096 and 1,000,000 by default. A low count makes a
	## captured proof cheaper to crack offline, which is what a server that is
	## not the real one would ask for. A high count costs the client CPU time,
	## about 3 ms per 4096 iterations. A minimum above the maximum would refuse
	## every count, so it fails with `MinIterationsAboveMax`, as does a
	## `max_iterations` below 4096 without a lower `min_iterations`.
	start : { username : Str, password : Str, nonce : List(U8), channel_binding : Scram.ChannelBinding, min_iterations ?: U64, max_iterations ?: U64 } -> Try(Scram.ClientFirst, [NonceTooShort(U64), EmptyChannelBinding, MinIterationsAboveMax])
	start = |{ username, password, nonce, channel_binding, min_iterations, max_iterations }|
		if nonce.len() < min_nonce_bytes {
			Err(NonceTooShort(nonce.len()))
		} else {
			begin({
				username,
				password,
				client_nonce: Base64.encode(nonce),
				channel_binding,
				min_iterations: min_iterations ?? 4096,
				max_iterations: max_iterations ?? 1_000_000,
			})
		}

	## An authentication waiting for the server's first message.
	ClientFirst :: {
		gs2_header : Str,
		bare : Str,
		client_nonce : Str,
		password : List(U8),
		binding_data : List(U8),
		plus : Bool,
		min_iterations : U64,
		max_iterations : U64,
	}.{

		## The mechanism to name to the server: SCRAM-SHA-256-PLUS with
		## `TlsServerEndPoint`, SCRAM-SHA-256 otherwise.
		mechanism : ClientFirst -> Str
		mechanism = |first| if first.plus Scram.mechanism_plus else Scram.mechanism

		## The client-first-message to send.
		message : ClientFirst -> Str
		message = |first| Str.concat(first.gs2_header, first.bare)

		## Read the server-first-message and work out the proof. Fails when
		## the message is malformed, names an extension this client must
		## understand but does not, does not extend the client's nonce, or asks
		## for an iteration count outside the bounds `start` was given.
		receive_server_first : ClientFirst, Str -> Try(Scram.ClientFinal, [InvalidServerFirst(Str), MandatoryExtension(Str), ServerNonceMismatch, InvalidSalt, IterationCountTooLow(U64), IterationCountTooHigh(U64)])
		receive_server_first = |first, server_first| {
			{ server_nonce, salt_text, iterations_text } = parse_server_first(server_first)?
			if !server_nonce.starts_with(first.client_nonce) or server_nonce.count_utf8_bytes() <= first.client_nonce.count_utf8_bytes() {
				Err(ServerNonceMismatch)
			} else if !server_nonce.to_utf8().all(is_nonce_byte) {
				Err(InvalidServerFirst("the nonce has characters outside printable ASCII"))
			} else {
				salt = Base64.decode(salt_text) ? |_| InvalidSalt
				count = parse_iterations(iterations_text)?
				if salt.is_empty() {
					Err(InvalidSalt)
				} else if count < first.min_iterations {
					Err(IterationCountTooLow(count))
				} else if count > first.max_iterations {
					Err(IterationCountTooHigh(count))
				} else {
					# A count of 0 gets this far only when `min_iterations` is 0.
					iterations = Hmac.iterations(count) ? |_| IterationCountTooLow(count)
					Ok(prove(first, server_first, server_nonce, salt, iterations))
				}
			}
		}
	}

	## An authentication that has its proof, waiting for the server's final
	## message.
	ClientFinal :: {
		final_message : Str,
		server_signature : Hmac,
	}.{

		## The client-final-message to send.
		message : ClientFinal -> Str
		message = |final| final.final_message

		## Check the server-final-message. `ServerError(reason)` is the server
		## refusing the authentication, with its `e=` reason such as
		## `invalid-proof` or `channel-bindings-dont-match`.
		## `ServerSignatureMismatch` is a server that does not know the
		## password: do not trust it. The signature is compared in constant
		## time.
		verify_server_final : ClientFinal, Str -> Try({}, [ServerError(Str), ServerSignatureMismatch, InvalidServerFinal(Str)])
		verify_server_final = |final, server_final| {
			attribute = server_final.split_on(",").first() ?? ""
			if attribute.starts_with("e=") {
				Err(ServerError(attribute.drop_prefix("e=")))
			} else if attribute.starts_with("v=") {
				match Base64.decode(attribute.drop_prefix("v=")) {
					Ok(signature) =>
						if Hmac.from_bytes(signature) == final.server_signature {
							Ok({})
						} else {
							Err(ServerSignatureMismatch)
						}
					Err(_) => Err(InvalidServerFinal("the verifier is not base64"))
				}
			} else {
				Err(InvalidServerFinal("expected v= or e="))
			}
		}
	}
}

## libpq sends 18 random bytes, the least this package accepts.
min_nonce_bytes = 18

## `start` with the nonce already in its text form. RFC 7677's test vector
## gives the nonce as text, so the tests start here.
begin : { username : Str, password : Str, client_nonce : Str, channel_binding : Scram.ChannelBinding, min_iterations : U64, max_iterations : U64 } -> Try(Scram.ClientFirst, [NonceTooShort(U64), EmptyChannelBinding, MinIterationsAboveMax])
begin = |{ username, password, client_nonce, channel_binding, min_iterations, max_iterations }| {
	{ gs2_header, binding_data, plus } =
		match channel_binding {
			Unsupported => { gs2_header: "n,,", binding_data: [], plus: Bool.False }
			ServerLacksPlus => { gs2_header: "y,,", binding_data: [], plus: Bool.False }
			TlsServerEndPoint(data) => { gs2_header: "p=tls-server-end-point,,", binding_data: data, plus: Bool.True }
		}
	if plus and binding_data.is_empty() {
		Err(EmptyChannelBinding)
	} else if min_iterations > max_iterations {
		Err(MinIterationsAboveMax)
	} else {
		Ok(
			Scram.ClientFirst.{
				gs2_header,
				bare: "n=${escape_username(username)},r=${client_nonce}",
				client_nonce,
				password: password.to_utf8(),
				binding_data,
				plus,
				min_iterations,
				max_iterations,
			},
		)
	}
}

## The proof and the signature to expect, from RFC 5802 section 3. The `_`
## is roc-hmac's checked iteration count, a type this package cannot name.
prove : Scram.ClientFirst, Str, Str, List(U8), _ -> Scram.ClientFinal
prove = |first, server_first, server_nonce, salt, iterations| {
	salted = Hmac.pbkdf2_sha256({ password: first.password, salt, iterations, length: 32 })
	client_key = Hmac.sha256({ key: salted, message: "Client Key".to_utf8() }).to_bytes()
	stored_key = Crypto.SHA256.hash(client_key).to_bytes()
	channel = Base64.encode(first.gs2_header.to_utf8().concat(first.binding_data))
	without_proof = "c=${channel},r=${server_nonce}"
	auth_message = "${first.bare},${server_first},${without_proof}".to_utf8()
	client_signature = Hmac.sha256({ key: stored_key, message: auth_message }).to_bytes()
	proof = client_key.map2(client_signature, |key, signature| key.bitwise_xor(signature))
	server_key = Hmac.sha256({ key: salted, message: "Server Key".to_utf8() }).to_bytes()
	Scram.ClientFinal.{
		final_message: "${without_proof},p=${Base64.encode(proof)}",
		server_signature: Hmac.sha256({ key: server_key, message: auth_message }),
	}
}

## Split the server-first-message into its nonce, salt and iteration count:
##
## ```text
## server-first-message = [reserved-mext ","] nonce "," salt "," iteration-count ["," extensions]
## ```
parse_server_first : Str -> Try({ server_nonce : Str, salt_text : Str, iterations_text : Str }, [InvalidServerFirst(Str), MandatoryExtension(Str)])
parse_server_first = |message| {
	parts = message.split_on(",")
	leading = parts.first() ?? ""
	if leading.starts_with("m=") {
		Err(MandatoryExtension(leading.drop_prefix("m=")))
	} else {
		match parts {
			[nonce, salt, iterations, ..] =>
				if nonce.starts_with("r=") and salt.starts_with("s=") and iterations.starts_with("i=") {
					Ok({ server_nonce: nonce.drop_prefix("r="), salt_text: salt.drop_prefix("s="), iterations_text: iterations.drop_prefix("i=") })
				} else {
					Err(InvalidServerFirst("expected r=, s= and i= in that order"))
				}
			_ => Err(InvalidServerFirst("expected r=, s= and i= in that order"))
		}
	}
}

## Digits without a leading zero, as RFC 5802's `posit-number`, so `+5`, ` 5`
## and `05` are refused rather than read. A lone `0` is left to the iteration
## bounds, which refuse it as too low.
parse_iterations : Str -> Try(U64, [InvalidServerFirst(Str)])
parse_iterations = |text|
	if text.is_empty() or !text.to_utf8().all(|byte| byte >= '0' and byte <= '9') {
		Err(InvalidServerFirst("the iteration count is not a number"))
	} else if text.starts_with("0") and text != "0" {
		Err(InvalidServerFirst("the iteration count has a leading zero"))
	} else {
		U64.from_str(text).map_err(|_| InvalidServerFirst("the iteration count is out of range"))
	}

## Printable ASCII without the comma, RFC 5802's `printable`.
is_nonce_byte : U8 -> Bool
is_nonce_byte = |byte| byte >= 0x21 and byte <= 0x7E and byte != ','

## RFC 5802's `saslname`: `=` becomes `=3D` and `,` becomes `=2C`.
escape_username : Str -> Str
escape_username = |name| name.replace_each("=", "=3D").replace_each(",", "=2C")

# ---- Tests ----

## `count` bytes counting up from `start`.
counting : U64, U64 -> List(U8)
counting = |start, count| List.repeat(0, count).map_with_index(|_, index| (start + index).to_u8_wrap())

## Run a start through the server's first message, with any failure as text.
final_of : Try(Scram.ClientFirst, [NonceTooShort(U64), EmptyChannelBinding, MinIterationsAboveMax]), Str -> Try(Scram.ClientFinal, Str)
final_of = |started_with, server_first|
	match started_with {
		Ok(first) => first.receive_server_first(server_first).map_err(Str.inspect)
		Err(err) => Err(Str.inspect(err))
	}

## A client-first built from a text nonce, with the iteration bounds wide open
## so the refusal tests cost nothing.
cheap : Str, Scram.ChannelBinding -> Try(Scram.ClientFirst, [NonceTooShort(U64), EmptyChannelBinding, MinIterationsAboveMax])
cheap = |client_nonce, channel_binding|
	begin({ username: "", password: "pw", client_nonce, channel_binding, min_iterations: 1, max_iterations: 1_000_000 })

## A start the test knows succeeds.
started : Try(Scram.ClientFirst, [NonceTooShort(U64), EmptyChannelBinding, MinIterationsAboveMax]) -> Scram.ClientFirst
started = |result|
	match result {
		Ok(first) => first
		Err(_) => {
			crash "the test's own start failed"
		}
	}

## The client-final-message `first` answers a server-first-message with, or
## why there is none.
answer : Scram.ClientFirst, Str -> Try(Str, _)
answer = |first, server_first| first.receive_server_first(server_first).map_ok(|final| final.message())

## [answer] from a client whose nonce is "abc".
receive : Str -> Try(Str, _)
receive = |server_first| answer(started(cheap("abc", Unsupported)), server_first)

## The two server messages of an exchange, and what the client says to them.
exchange : Try(Scram.ClientFirst, [NonceTooShort(U64), EmptyChannelBinding, MinIterationsAboveMax]), Str, Str -> Try({ first : Str, final : Str, verified : Try({}, [ServerError(Str), ServerSignatureMismatch, InvalidServerFinal(Str)]) }, Str)
exchange = |started_with, server_first, server_final| {
	first_message = started_with.map_ok(|first| first.message()).map_err(Str.inspect)?
	final = final_of(started_with, server_first)?
	Ok({ first: first_message, final: final.message(), verified: final.verify_server_final(server_final) })
}

# RFC 7677 section 3, the published test vector.
expect
	exchange(
		begin({ username: "user", password: "pencil", client_nonce: "rOprNGfwEbeRWgbNEkqO", channel_binding: Unsupported, min_iterations: 4096, max_iterations: 4096 }),
		"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
		"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=",
	)
		== Ok({
			first: "n,,n=user,r=rOprNGfwEbeRWgbNEkqO",
			final: "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
			verified: Ok({}),
		})

# The vectors below were computed with Python's hashlib and hmac, an
# implementation independent of this one, from 18 nonce bytes counting up
# from 1, 50 and 200.

# An escaped username, the `y` flag and a non-ASCII password.
expect
	exchange(
		Scram.start({ username: "us=er,name", password: "pässword with spaces", nonce: counting(1, 18), channel_binding: ServerLacksPlus }),
		"r=AQIDBAUGBwgJCgsMDQ4PEBESQ7x&k!2,s=ZGVmZ2hpamtsbW5vcHFycw==,i=4096",
		"v=Mm3Ys2w308bsdpwRQhdfRjh8rNsnqO2Kb4gHx/NhfBQ=",
	)
		== Ok({
			first: "y,,n=us=3Der=2Cname,r=AQIDBAUGBwgJCgsMDQ4PEBES",
			final: "c=eSws,r=AQIDBAUGBwgJCgsMDQ4PEBESQ7x&k!2,p=IdX8BWaRk1nOHuOKnGDDb16xpz6xxB1Dc1ulBPGFKdk=",
			verified: Ok({}),
		})

# SCRAM-SHA-256-PLUS with a 32-byte end point, as a SHA-256 hash gives.
expect
	exchange(
		Scram.start({ username: "", password: "correct horse battery staple", nonce: counting(50, 24), channel_binding: TlsServerEndPoint(counting(0, 32)), min_iterations: 5000 }),
		"r=MjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJsrv+nonce/9,s=c2FsdHNhbHRzYWx0,i=5000",
		"v=tjYh6i12C0l3QMw0c7i5d6AEQBmLqdLa8vK0bQJakBg=",
	)
		== Ok({
			first: "p=tls-server-end-point,,n=,r=MjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJ",
			final: "c=cD10bHMtc2VydmVyLWVuZC1wb2ludCwsAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=,r=MjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJsrv+nonce/9,p=sb/hE25BSUFq9/9PgXy9mjCXLkGLu2ObSJIx2eCAuPs=",
			verified: Ok({}),
		})

# SCRAM-SHA-256-PLUS with a 48-byte end point, as a SHA-384 hash gives.
expect
	exchange(
		Scram.start({ username: "", password: "pencil", nonce: counting(200, 18), channel_binding: TlsServerEndPoint(counting(10, 48)) }),
		"r=yMnKy8zNzs/Q0dLT1NXW19jZabc,s=AP8B/g==,i=4096",
		"v=s1qD+t2zAKx4wl3oct2zddgzMdJI61GdczLdS7QrWpo=",
	)
		== Ok({
			first: "p=tls-server-end-point,,n=,r=yMnKy8zNzs/Q0dLT1NXW19jZ",
			final: "c=cD10bHMtc2VydmVyLWVuZC1wb2ludCwsCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5,r=yMnKy8zNzs/Q0dLT1NXW19jZabc,p=w2q/gZ2Y257uzNST/ypGU6N4faTsLmHHzzvSmVM6qvw=",
			verified: Ok({}),
		})

# The mechanism follows the channel binding.
expect cheap("abc", TlsServerEndPoint([1])).map_ok(|first| first.mechanism()) == Ok("SCRAM-SHA-256-PLUS")
expect cheap("abc", ServerLacksPlus).map_ok(|first| first.mechanism()) == Ok("SCRAM-SHA-256")
expect cheap("abc", Unsupported).map_ok(|first| first.mechanism()) == Ok("SCRAM-SHA-256")

# ---- Refusals before any exchange ----

expect {
	result = Scram.start({ username: "", password: "pw", nonce: List.repeat(7, 17), channel_binding: Unsupported })
	match result {
		Err(NonceTooShort(17)) => Bool.True
		_ => Bool.False
	}
}

expect
	match cheap("abc", TlsServerEndPoint([])) {
		Err(EmptyChannelBinding) => Bool.True
		_ => Bool.False
	}

# ---- Refusals of the server-first-message ----

expect receive("m=must-understand,r=abcdef,s=c2FsdA==,i=1") == Err(MandatoryExtension("must-understand"))
expect receive("r=abcdef,s=c2FsdA==") == Err(InvalidServerFirst("expected r=, s= and i= in that order"))
expect receive("s=c2FsdA==,r=abcdef,i=1") == Err(InvalidServerFirst("expected r=, s= and i= in that order"))
expect receive("") == Err(InvalidServerFirst("expected r=, s= and i= in that order"))

# Each attribute needs its name.
expect receive("abcdef,s=c2FsdA==,i=1") == Err(InvalidServerFirst("expected r=, s= and i= in that order"))
expect receive("r=abcdef,c2FsdA==,i=1") == Err(InvalidServerFirst("expected r=, s= and i= in that order"))
expect receive("r=abcdef,s=c2FsdA==,1") == Err(InvalidServerFirst("expected r=, s= and i= in that order"))

# The server's nonce must extend the client's, by at least one character.
expect receive("r=xyzdef,s=c2FsdA==,i=1") == Err(ServerNonceMismatch)
expect receive("r=abc,s=c2FsdA==,i=1") == Err(ServerNonceMismatch)
expect receive("r=ab,s=c2FsdA==,i=1") == Err(ServerNonceMismatch)

# Containing the client's nonce somewhere else is not extending it.
expect receive("r=xabcdef,s=c2FsdA==,i=1") == Err(ServerNonceMismatch)

# Printable ASCII is 0x21 to 0x7E, so a space, DEL and anything past ASCII
# are refused.
expect receive("r=abc def,s=c2FsdA==,i=1") == Err(InvalidServerFirst("the nonce has characters outside printable ASCII"))
expect receive("r=abc\u(7F),s=c2FsdA==,i=1") == Err(InvalidServerFirst("the nonce has characters outside printable ASCII"))
expect receive("r=abcdé,s=c2FsdA==,i=1") == Err(InvalidServerFirst("the nonce has characters outside printable ASCII"))
expect receive("r=abc!~,s=c2FsdA==,i=1").is_ok()

expect receive("r=abcdef,s=not base64!,i=1") == Err(InvalidSalt)
expect receive("r=abcdef,s=,i=1") == Err(InvalidSalt)

expect receive("r=abcdef,s=c2FsdA==,i=") == Err(InvalidServerFirst("the iteration count is not a number"))
expect receive("r=abcdef,s=c2FsdA==,i=+5") == Err(InvalidServerFirst("the iteration count is not a number"))
expect receive("r=abcdef,s=c2FsdA==,i=5x") == Err(InvalidServerFirst("the iteration count is not a number"))
expect receive("r=abcdef,s=c2FsdA==,i=05") == Err(InvalidServerFirst("the iteration count has a leading zero"))
expect receive("r=abcdef,s=c2FsdA==,i=10").is_ok()
expect receive("r=abcdef,s=c2FsdA==,i=99999999999999999999999") == Err(InvalidServerFirst("the iteration count is out of range"))
expect receive("r=abcdef,s=c2FsdA==,i=0") == Err(IterationCountTooLow(0))

# Extensions after the iteration count are ignored.
expect receive("r=abcdef,s=c2FsdA==,i=1,x=something").is_ok()
expect receive("r=abcdef,s=c2FsdA==,i=1").is_ok()

# ---- The iteration bounds `start` sets ----

## 18 nonce bytes of 1, "AQEBAQEBAQEBAQEBAQEBAQEB" in base64.
ones = List.repeat(1, 18)

## What a client started with the `ones` nonce answers a server asking for
## `count` iterations.
asked : Try(Scram.ClientFirst, [NonceTooShort(U64), EmptyChannelBinding, MinIterationsAboveMax]), U64 -> Try(Str, _)
asked = |start_result, count| answer(started(start_result), "r=AQEBAQEBAQEBAQEBAQEBAQEBxyz,s=c2FsdA==,i=${count.to_str()}")

# The defaults: at least 4096, at most 1,000,000.
expect asked(Scram.start({ username: "", password: "pw", nonce: ones, channel_binding: Unsupported }), 4095) == Err(IterationCountTooLow(4095))
expect asked(Scram.start({ username: "", password: "pw", nonce: ones, channel_binding: Unsupported }), 1_000_001) == Err(IterationCountTooHigh(1_000_001))

# A minimum given to `start` replaces the default, above it and below it.
expect asked(Scram.start({ username: "", password: "pw", nonce: ones, channel_binding: Unsupported, min_iterations: 10_000 }), 5000) == Err(IterationCountTooLow(5000))
expect asked(Scram.start({ username: "", password: "pw", nonce: ones, channel_binding: Unsupported, min_iterations: 1 }), 1).is_ok()

# So does a maximum.
expect asked(Scram.start({ username: "", password: "pw", nonce: ones, channel_binding: Unsupported, max_iterations: 4096 }), 4097) == Err(IterationCountTooHigh(4097))
expect asked(Scram.start({ username: "", password: "pw", nonce: ones, channel_binding: Unsupported, min_iterations: 1, max_iterations: 4 }), 5) == Err(IterationCountTooHigh(5))

# A minimum of 0 still refuses a count of 0, which PBKDF2 cannot run.
expect asked(Scram.start({ username: "", password: "pw", nonce: ones, channel_binding: Unsupported, min_iterations: 0 }), 0) == Err(IterationCountTooLow(0))

# A minimum above the maximum, here the default minimum of 4096, would refuse
# every count.
expect
	match Scram.start({ username: "", password: "pw", nonce: ones, channel_binding: Unsupported, max_iterations: 1000 }) {
		Err(MinIterationsAboveMax) => Bool.True
		_ => Bool.False
	}

# ---- The server-final-message ----

## The client-final of [receive]'s client, for a server-first-message the
## test knows it accepts.
finished : Str -> Scram.ClientFinal
finished = |server_first|
	match started(cheap("abc", Unsupported)).receive_server_first(server_first) {
		Ok(final) => final
		Err(_) => {
			crash "the test's own exchange failed"
		}
	}

verify : Str -> Try({}, [ServerError(Str), ServerSignatureMismatch, InvalidServerFinal(Str)])
verify = |server_final| finished("r=abcdef,s=c2FsdA==,i=1").verify_server_final(server_final)

expect verify("e=invalid-proof") == Err(ServerError("invalid-proof"))
expect verify("e=channel-bindings-dont-match,x=y") == Err(ServerError("channel-bindings-dont-match"))
expect verify("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") == Err(ServerSignatureMismatch)
expect verify("v=AA==") == Err(ServerSignatureMismatch)
expect verify("v=") == Err(ServerSignatureMismatch)
expect verify("v=not base64") == Err(InvalidServerFinal("the verifier is not base64"))
expect verify("ok") == Err(InvalidServerFinal("expected v= or e="))
expect verify("") == Err(InvalidServerFinal("expected v= or e="))

# A correct signature followed by an extension still verifies.
expect
	exchange(
		begin({ username: "user", password: "pencil", client_nonce: "rOprNGfwEbeRWgbNEkqO", channel_binding: Unsupported, min_iterations: 4096, max_iterations: 4096 }),
		"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
		"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=,x=extension",
	).map_ok(|exchanged| exchanged.verified)
		== Ok(Ok({}))

# ---- Choosing the channel binding ----

# Every combination of what the server offered, the transport and the
# requirement.

both = [Scram.mechanism_plus, Scram.mechanism]

plain_only = [Scram.mechanism]

plus_only = [Scram.mechanism_plus]

pick = |offered, transport, require_channel_binding| Scram.select({ offered, transport, require_channel_binding })

# TLS with an end point value binds whenever PLUS is offered.
expect pick(both, TlsWithEndPoint([1]), Bool.False) == Ok(TlsServerEndPoint([1]))
expect pick(both, TlsWithEndPoint([1]), Bool.True) == Ok(TlsServerEndPoint([1]))
expect pick(plus_only, TlsWithEndPoint([1]), Bool.False) == Ok(TlsServerEndPoint([1]))
expect pick(plus_only, TlsWithEndPoint([1]), Bool.True) == Ok(TlsServerEndPoint([1]))

# Over TLS, a server without PLUS gets `y`, so a stripped offer is caught.
expect pick(plain_only, TlsWithEndPoint([1]), Bool.False) == Ok(ServerLacksPlus)
expect pick(plain_only, TlsWithEndPoint([1]), Bool.True) == Err(ChannelBindingRequired)

# TLS without an end point value cannot bind.
expect pick(both, Tls, Bool.False) == Ok(Unsupported)
expect pick(both, Tls, Bool.True) == Err(ChannelBindingUnavailable)
expect pick(plain_only, Tls, Bool.False) == Ok(Unsupported)
expect pick(plain_only, Tls, Bool.True) == Err(ChannelBindingUnavailable)
expect pick(plus_only, Tls, Bool.False) == Err(ScramNotOffered)
expect pick(plus_only, Tls, Bool.True) == Err(ChannelBindingUnavailable)

# Neither can plain TCP.
expect pick(both, Plain, Bool.False) == Ok(Unsupported)
expect pick(both, Plain, Bool.True) == Err(ChannelBindingUnavailable)
expect pick(plain_only, Plain, Bool.False) == Ok(Unsupported)
expect pick(plain_only, Plain, Bool.True) == Err(ChannelBindingUnavailable)
expect pick(plus_only, Plain, Bool.False) == Err(ScramNotOffered)
expect pick(plus_only, Plain, Bool.True) == Err(ChannelBindingUnavailable)

# Without either SCRAM-SHA-256 mechanism nothing else matters.
expect pick([], TlsWithEndPoint([1]), Bool.False) == Err(ScramNotOffered)
expect pick([], TlsWithEndPoint([1]), Bool.True) == Err(ScramNotOffered)
expect pick(["SCRAM-SHA-1", "PLAIN"], Plain, Bool.False) == Err(ScramNotOffered)

expect escape_username("a=b,c") == "a=3Db=2Cc"
