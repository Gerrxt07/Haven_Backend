# Haven Backend Deploy Helpers

## Auto Pull Deploy

`auto-pull-deploy.sh` checks `origin/master`. If a new commit exists, it pulls with `--ff-only` and rebuilds the Docker Compose service.

It refuses to run when local changes exist or when the local branch diverged from the remote.

Run once:

```sh
./scripts/auto-pull-deploy.sh
```

Install the user timer:

```sh
./scripts/install-auto-pull-service.sh
```

The timer polls every 60 seconds.

Check status:

```sh
systemctl --user status haven-backend-auto-pull.timer
systemctl --user status haven-backend-auto-pull.service
```

Stop it:

```sh
systemctl --user disable --now haven-backend-auto-pull.timer
```
