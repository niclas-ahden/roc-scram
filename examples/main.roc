## Authenticate with SCRAM-SHA-256-PLUS, playing both sides of a recorded
## exchange: the server's messages were computed with Python's hashlib, for
## password "pencil", 18 nonce bytes counting up from 200 and a 48-byte
## `tls-server-end-point` value counting up from 10.
app [main!] {
	pf: platform "https://github.com/roc-lang/basic-cli/releases/download/0.26.0/GddgvsGjiNXrHFW6au5i5dUDbTs8FinQdrgE2Gqmw53t.tar.zst",
	scram: "../package/main.roc",
}

import pf.Random
import pf.Stdout
import scram.Scram

main! = |_args| {
	# The recorded end point. A real client takes the TLS connection's
	# `tls-server-end-point` value from its platform.
	end_point = counting(10, 48)
	binding = Scram.select({
		offered: ["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"],
		transport: TlsWithEndPoint(end_point),
		require_channel_binding: Bool.True,
	})?

	# A real client uses random bytes, see `random_nonce!` below. The
	# recorded exchange needs the nonce it was recorded with.
	fresh = random_nonce!()?
	Stdout.line!("a random nonce has ${fresh.len().to_str()} bytes")?

	first = Scram.start({ username: "", password: "pencil", nonce: counting(200, 18), channel_binding: binding })?
	Stdout.line!("${first.mechanism()}: ${first.message()}")?

	final = first.receive_server_first("r=yMnKy8zNzs/Q0dLT1NXW19jZabc,s=AP8B/g==,i=4096")?
	Stdout.line!("client-final: ${final.message()}")?

	final.verify_server_final("v=s1qD+t2zAKx4wl3oct2zddgzMdJI61GdczLdS7QrWpo=")?
	Stdout.line!("the server proved it knows the password")?

	# A server that does not know the password cannot produce the signature.
	match final.verify_server_final("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") {
		Err(ServerSignatureMismatch) => Stdout.line!("an impostor's signature is refused")?
		other => Stdout.line!("an impostor's signature: ${Str.inspect(other)}")?
	}
	Ok({})
}

## 24 random bytes from the operating system: three `Random.seed_u64!` calls.
random_nonce! : () => Try(List(U8), _)
random_nonce! = || {
	a = Random.seed_u64!()?
	b = Random.seed_u64!()?
	c = Random.seed_u64!()?
	Ok(u64_bytes(a).concat(u64_bytes(b)).concat(u64_bytes(c)))
}

u64_bytes : U64 -> List(U8)
u64_bytes = |value| List.repeat(0, 8).map_with_index(|_, index| value.shr_zf_wrap((index * 8).to_u8_wrap()).to_u8_wrap())

## `count` bytes counting up from `start`.
counting : U64, U64 -> List(U8)
counting = |start, count| List.repeat(0, count).map_with_index(|_, index| (start + index).to_u8_wrap())
