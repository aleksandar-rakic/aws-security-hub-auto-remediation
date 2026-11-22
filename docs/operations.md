# Operating the remediator

Commands assume the Security Hub administrator account and its aggregation region,
`FUNCTION=security-hub-remediation` and `REGION=eu-central-1`.

## Rolling out

1. **Dry run, few controls.** Deploy with `dry_run = true` and the controls whose fixes
   nobody will miss (S3.1, S3.8, EC2.7, KMS.4, SQS.1, ECR.1).
2. **Read the notes for a week.** Every matched finding gets *"Dry run, nothing changed.
   Would have: …"*. List them:

   ```bash
   aws securityhub get-findings --region "$REGION" --filters '{
     "NoteUpdatedBy": [{"Value": "security-hub-auto-remediation", "Comparison": "EQUALS"}],
     "WorkflowStatus": [{"Value": "NOTIFIED", "Comparison": "EQUALS"}]
   }' --query 'Findings[].[Compliance.SecurityControlId, Resources[0].Id, Note.Text]' --output table
   ```

3. **Tag what must stay as it is** (`auto-remediation=skip`): a public website bucket, a
   bastion that needs SSH from the internet, a queue owned by another team.
4. **Leave dry run** (`dry_run = false`), then add the controls that touch running workloads:
   EC2.2, EC2.8, EC2.13/14/53/54, S3.5, RDS.1, EC2.1. EC2.19 and instance quarantine last,
   after the owners of public services and the incident-response team have agreed.

## What happened to a resource

Each decision is one JSON log line with the finding, control, account, resource,
outcome and note:

```bash
aws logs filter-log-events --region "$REGION" --log-group-name "/aws/lambda/$FUNCTION" \
  --filter-pattern '{ $.message = "*sg-0123456789abcdef0*" }' \
  --query 'events[].message' --output text
```

The same note is on the finding in the Security Hub console (Workflow status and History).

## Failed remediations and the dead-letter queue

A failure leaves the finding `NOTIFIED` with the error, retries twice, then puts the event in
`$FUNCTION-dlq` and raises the `$FUNCTION-dead-letters` alarm. Usual causes: the member role
is missing in a new account, an SCP denies the change, or the resource was deleted meanwhile.

Fix the cause, then replay the events (the actions are idempotent, so replays are safe):

```bash
QUEUE_URL=$(aws sqs get-queue-url --region "$REGION" --queue-name "$FUNCTION-dlq" \
  --query QueueUrl --output text)

# Lambda on-failure records hold the original event under requestPayload;
# EventBridge delivery failures hold the event itself.
aws sqs receive-message --region "$REGION" --queue-url "$QUEUE_URL" --max-number-of-messages 10 \
  --query 'Messages[].Body' --output json | jq -c '.[] | fromjson | .requestPayload // .' |
  while read -r payload; do
    aws lambda invoke --region "$REGION" --function-name "$FUNCTION" \
      --cli-binary-format raw-in-base64-out --payload "$payload" /dev/stdout
  done
```

Delete the messages once the replays succeed. Findings that stay `NOTIFIED` are reopened by
setting their workflow back to `NEW`, which makes the EventBridge rule match them again on
the next import.

## Undoing a change

The note on each finding says exactly what was changed, so it can be put back by hand:

| Control | Undo |
| --- | --- |
| S3.1 / S3.8 | `aws s3control delete-public-access-block --account-id …` / `aws s3api delete-public-access-block --bucket …` |
| S3.5 | Remove the `DenyInsecureTransport` statement from the bucket policy |
| EC2.2 / EC2.13 / EC2.14 / EC2.19 / EC2.53 / EC2.54 | `aws ec2 authorize-security-group-ingress` with the protocol, ports and CIDR listed in the note |
| EC2.8 | `aws ec2 modify-instance-metadata-options --instance-id … --http-tokens optional` |
| EC2.1 / RDS.1 | Re-add `all` to `createVolumePermission` / the `restore` attribute (rarely the right call) |
| KMS.4, EC2.7, SQS.1, ECR.1 | Safe to leave; turning them off again is a separate, deliberate change |

Then tag the resource `auto-remediation=skip`, or the next finding will change it again.

## Releasing a quarantined instance

Quarantine keeps the instance running in `quarantine-no-traffic`, snapshots its volumes
(tag `quarantine-instance`) and records the original groups in the tag
`quarantine-previous-groups`. After the investigation:

```bash
INSTANCE=i-0123456789abcdef0
GROUPS=$(aws ec2 describe-tags --region "$REGION" \
  --filters "Name=resource-id,Values=$INSTANCE" "Name=key,Values=quarantine-previous-groups" \
  --query 'Tags[0].Value' --output text)
aws ec2 modify-instance-attribute --region "$REGION" --instance-id "$INSTANCE" --groups $GROUPS
aws ec2 delete-tags --region "$REGION" --resources "$INSTANCE" \
  --tags Key=quarantine Key=quarantine-previous-groups
```

A compromised instance is usually replaced rather than released; keep the snapshots for as
long as your incident-retention policy requires.

## Adding an account

Apply `terraform/member-role` in the new account (ideally from the account-vending pipeline).
Until then its findings are `NOTIFIED` with *"no member role is configured"* or an
`AccessDenied` from `sts:AssumeRole`.
