# charon-ssh

SSH transport, PTY sessions and host-key TOFU, extracted from
[Charon](https://github.com/builtbyfood/charon) so other applications can share
one implementation.
[morpheus-certificate-install](https://github.com/builtbyfood/morpheus-certificate-install)
uses it for its appliance connection.

Deliberately free of tauri, rusqlite, serialport and portable-pty: output
reaches a UI over plain channels, and an unknown host key is put to the user
through the `HostKeyPolicy` trait, so each application decides both for
itself.

`SshSession::exec_stdin` exists so a password can reach `sudo -S` on stdin
without ever appearing on a command line.

## Using it

It isn't on crates.io. Depend on a tagged commit:

```toml
charon-ssh = { git = "https://github.com/builtbyfood/charon-ssh", tag = "v0.2.1" }
```

## Versions

- **0.2.1:** a host key of a different *type* from the one on file is reported
  as `Changed`, not `Unknown`. Before, a host with an ed25519 key on file that
  was offered an RSA key looked like a first meeting, so a trust-on-first-use
  policy could learn the new key. Upgrade if you use 0.2.0.
- **0.2.0:** russh 0.65 (RUSTSEC-2026-0153, RUSTSEC-2026-0154),
  `SshSession::is_closed`, `SshError::AuthRejected`, `HostKeys::with_label`,
  `exec_stdin` with no command sends end-of-input, `exec_cancellable` /
  `ExecHandle`, `connect_exec` / `open_shell` / `Shell`, `Auth::Agent` /
  `Auth::Auto`, and `SshSession::server_key`.

## License

Apache-2.0, see [LICENSE](LICENSE).
