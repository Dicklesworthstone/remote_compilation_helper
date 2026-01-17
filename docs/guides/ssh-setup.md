# SSH Setup Guide

This guide walks you through setting up SSH access to RCH workers, from key
creation to troubleshooting.

## 1. Generate SSH Keys

Use modern Ed25519 keys (fast and secure). You can use your default key or
create a dedicated key for RCH.

```bash
# Default key
ssh-keygen -t ed25519 -a 64 -C "rch-worker-access"

# Optional: dedicated key for RCH
ssh-keygen -t ed25519 -a 64 -f ~/.ssh/rch_worker -C "rch-worker-access"
```

Notes:
- Default key path is `~/.ssh/id_ed25519`.
- Use a passphrase when possible; SSH agents make this painless.
- `-a 64` increases KDF rounds for better protection if the key is stolen.

## 2. Copy Your Public Key to the Worker

### Option A: ssh-copy-id (Linux or macOS with Homebrew)

```bash
# If you used a dedicated key
ssh-copy-id -i ~/.ssh/rch_worker.pub user@worker-host

# If you used the default key
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@worker-host
```

On macOS, `ssh-copy-id` is available via Homebrew:

```bash
brew install ssh-copy-id
```

### Option B: Manual authorized_keys

```bash
# Create ~/.ssh on the worker and set permissions
ssh user@worker-host "mkdir -p ~/.ssh && chmod 700 ~/.ssh"

# Append your public key
cat ~/.ssh/id_ed25519.pub | ssh user@worker-host "cat >> ~/.ssh/authorized_keys"

# Fix permissions on the worker
ssh user@worker-host "chmod 600 ~/.ssh/authorized_keys"
```

If you used a dedicated key, replace `id_ed25519.pub` with your key name.

## 3. Test the Connection

```bash
ssh -i ~/.ssh/id_ed25519 user@worker-host "echo OK"
```

If this prints `OK`, SSH is working.

Tip: Use an SSH alias in `~/.ssh/config` so you can use short names in
`workers.toml`.

## 4. SSH Agent Setup (Recommended)

### macOS

```bash
# Start agent for this shell
eval "$(ssh-agent -s)"

# Add key to agent and keychain
ssh-add --apple-use-keychain ~/.ssh/id_ed25519
```

Add to `~/.ssh/config`:

```
Host *
  UseKeychain yes
  AddKeysToAgent yes
```

### Linux

```bash
# Start agent for this shell
eval "$(ssh-agent -s)"

# Add key
ssh-add ~/.ssh/id_ed25519
```

### Windows (PowerShell)

```powershell
# Enable and start the agent service
Get-Service ssh-agent | Set-Service -StartupType Automatic
Start-Service ssh-agent

# Add key
ssh-add $env:USERPROFILE\.ssh\id_ed25519
```

## 5. Advanced Configurations

### SSH Config Shortcuts

`~/.ssh/config`:

```
Host rch-worker-1
  HostName 203.0.113.10
  User ubuntu
  IdentityFile ~/.ssh/rch_worker
```

Then in `workers.toml` you can use:

```toml
host = "rch-worker-1"
```

### Bastion / Jump Hosts (ProxyJump)

```
Host rch-bastion
  HostName bastion.example.com
  User admin
  IdentityFile ~/.ssh/bastion_key

Host rch-worker-*
  ProxyJump rch-bastion
  User ubuntu
  IdentityFile ~/.ssh/rch_worker

Host rch-worker-1
  HostName 10.0.1.10
```

### SSH Multiplexing (Faster Connections)

```
Host *
  ControlMaster auto
  ControlPath ~/.ssh/cm-%r@%h:%p
  ControlPersist 10m
```

This keeps a connection open for reuse (faster `rsync` and probes).

## 6. Troubleshooting

### Permission denied (publickey)

- Ensure the right key is used: `ssh -i ~/.ssh/id_ed25519 user@host`
- Verify server file permissions:
  - `~/.ssh` is `700`
  - `~/.ssh/authorized_keys` is `600`
- Check that the correct user is listed in `workers.toml`.

### Host key verification failed

```bash
ssh-keygen -R worker-host
ssh user@worker-host
```

### Connection timeout

- Verify the host is reachable and port 22 is open.
- Run a verbose SSH command:

```bash
ssh -vvv user@worker-host
```

### Agent forwarding not working

- Use `ssh -A` to forward your agent.
- Or add to `~/.ssh/config`:

```
Host rch-worker-*
  ForwardAgent yes
```

## 7. Next Steps

- [Configure workers](./workers.md)
- [Troubleshoot SSH and RCH issues](../TROUBLESHOOTING.md)
