#!/usr/bin/env bash
# Checks that the bench left nothing in your clouds: VMs, disks, firewall rules, key pairs and security groups that its
# hardware runs and the Demo Bank create (named tacra-* or demobank-*, labelled or tagged purpose=tacra-* or
# demo-bank). Each run deletes what it made and checks; this is the same check, by hand, for both clouds at once. A cloud
# whose CLI is missing or not signed in is skipped and says so. Exits non-zero when something is left.
#
#   scripts/cloud-check.sh        (make cloud-check)
#
# GCP_PROJECT, AWS_REGION: which project and region to look in (scripts/lib.sh).
set -uo pipefail
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
left=0 unknown=0
count() { # LABEL COMMAND...: prints how many resources the command lists; a command that fails counts as left
  local out rc n
  out="$("${@:2}" 2>/dev/null)"
  rc=$?
  if [ "$rc" != 0 ]; then
    printf '  %-58s %s\n' "$1" "could not check (the command failed, exit $rc)"
    unknown=1
    return
  fi
  n="$(printf '%s\n' "$out" | wc -w | tr -d ' ')"   # names or ids, one word each
  printf '  %-58s %s\n' "$1" "$n"
  [ "$n" = 0 ] || left=1
}

if command -v gcloud >/dev/null 2>&1 && [ -n "$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null)" ] \
  && { [ -n "${GCP_PROJECT:-}" ] || [ -n "$(gcloud config get-value project 2>/dev/null)" ]; }; then
  bench_gcp
  count "instances labelled purpose=tacra-* or demo-bank" gcloud compute instances list --project="$GCP_PROJECT" \
    --filter='labels.purpose~^tacra- OR labels.purpose=demo-bank' --format='value(name)'
  count "disks named tacra-* or demobank-*" gcloud compute disks list --project="$GCP_PROJECT" \
    --filter='name~^tacra- OR name~^demobank-' --format='value(name)'
  count "firewall rules named tacra-* or demobank-*" gcloud compute firewall-rules list --project="$GCP_PROJECT" \
    --filter='name~^tacra- OR name~^demobank-' --format='value(name)'
else
  echo "== Google Cloud: not checked (no signed-in gcloud with a project)"
fi

if command -v aws >/dev/null 2>&1 && aws sts get-caller-identity --region "$AWS_REGION" >/dev/null 2>&1; then
  bench_aws
  count "instances tagged purpose=tacra-* or demo-bank, not terminated" aws ec2 describe-instances --region "$AWS_REGION" \
    --filters 'Name=tag:purpose,Values=tacra-*,demo-bank' 'Name=instance-state-name,Values=pending,running,stopping,stopped' \
    --query 'Reservations[].Instances[].InstanceId' --output text
  count "key pairs named tacra-* or demobank-*" aws ec2 describe-key-pairs --region "$AWS_REGION" \
    --filters 'Name=key-name,Values=tacra-*,demobank-*' --query 'KeyPairs[].KeyName' --output text
  count "security groups named tacra-* or demobank-*" aws ec2 describe-security-groups --region "$AWS_REGION" \
    --filters 'Name=group-name,Values=tacra-*,demobank-*' --query 'SecurityGroups[].GroupId' --output text
else
  echo "== AWS: not checked (no signed-in AWS CLI)"
fi

[ "$left" = 0 ] || bench_die "something is left: delete it in the cloud's console or CLI"
[ "$unknown" = 0 ] || bench_die "some checks could not run: see above"
echo "cloud-check: nothing left"
