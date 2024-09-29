# High refresh rate mouse fix

Recently my mouse broke, so I bought a new one. Cue my surprise when
I found stuff breaking after connecting the new mouse to my PC. Surely
it can't be the new mouse's fault?!

Unfortunately it was. Apparently there is poorly written software out
there which breaks horribly when it gets too many mouse events per second,
and my new rodent just so happend to be very fast, 8000 Hz fast to be exact.

So this program fixes the issue and throttles relative mouse events to ~500 Hz
by default, which I found works decent.

## How to use

Install [Rust](https://www.rust-lang.org), then build it:

```
cargo build --release
```

Then run it:

```
sudo ./target/release/highhz-mouse-fix
```

You can use the `--target-hz` argument to pick a different target polling rate.
