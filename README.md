THE SOFTWARE IS PROVIDED "AS IS" AND VINZENT STEINBERG AND THE AUTHORS DISCLAIM
ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL VINZENT STEINBERG OR THE AUTHORS
BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


# aesrng

A fast-key-erasure random-number generator using the AES-NI instruction set,
designed to fill large buffer with random bytes.

It was ported from a [C implementation](https://github.com/jedisct1/aes-stream).


## Compilation

A CPU supporting the AES-NI instructions is required. To allow Rust to use these
instructions, the following flags are recommended:

```
RUSTFLAGS='-C target-feature=+aes -C target-cpu=native'
```


## Performance

Performance is comparable to the fastest non-crypto RNGs. Here is a comparison
with [xoroshiro](https://github.com/vks/xoroshiro) and Rand's default RNG when
generating 100 MiB of random data:

![](violin.svg)

Note that this is not a fair comparison, because the other RNGs are not using
explicit vectorization.
