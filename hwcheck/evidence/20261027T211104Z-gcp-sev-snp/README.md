# A run that stopped before the guest answered

The bench ran on a Google Cloud VM under its service account, and the guest was made with OS Login. The service
account could not import its ssh key into OS Login (`ssh.stderr`: `INVALID_ARGUMENT`), so the guest never answered,
and the run deleted it after its wait. Since `b6daa506` the guest takes the bench's ssh key in its own metadata, with
OS Login off, and the runs of the same day after it passed.
