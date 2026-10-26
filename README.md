
# AWS Security Alert Triage Lab

Built my own detection and alerting pipeline in AWS, then staged a multi-stage attack against my own account and investigated it end to end: detection, triage, and containment.

The original plan was to use Amazon GuardDuty. My account landed in AWS's new "project" sign-up, which blocks GuardDuty unless you activate advanced features (irreversible, and it removes the account spend limit). So instead of letting AWS do the detection for me, I wrote the detections myself with CloudTrail, EventBridge, and SNS. That turned out to be a better exercise anyway, because I had to decide what malicious activity looks like and write the logic to catch it.

All activity happened in a personal lab account in us-east-2. Account ID and my home IP are redacted in this writeup.

## How I think about the tools

Coming from a SOC background, I mapped the AWS services to what I already use day to day:

| AWS service | What it does here | Closest equivalent |
|---|---|---|
| CloudTrail | Records every API action in the account | The log source (Splunk) |
| EventBridge | Matches events against my detection logic and routes them | Correlation / detection rules |
| SNS | Emails me when a rule fires | Alerting / notification |

## Architecture

```
CloudTrail (management events)
        |
        v
EventBridge default bus  --->  3 event-pattern rules
        |
        v
SNS topic (lab-security-alerts)  --->  email alert (formatted, not raw JSON)
```

## Detections I built

I focused on actions that happen in my own region and that map to real attacker behavior. Each rule fires on a specific CloudTrail event, then an SNS input transformer turns the raw JSON into a readable one-line alert.

### Rule 1: CloudTrail tampering
Attackers stop logging to hide their tracks. This fires on anyone stopping, deleting, or reconfiguring the trail.

```json
{
  "source": ["aws.cloudtrail"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["cloudtrail.amazonaws.com"],
    "eventName": ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]
  }
}
```
MITRE ATT&CK: T1562.008, Impair Defenses: Disable or Modify Cloud Logs.

### Rule 2: Security group opened to the internet
A security group allowing 0.0.0.0/0 means the environment is exposed to the whole internet. This fires when an inbound rule is added with that CIDR.

```json
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": ["AuthorizeSecurityGroupIngress"],
    "requestParameters": {
      "ipPermissions": {
        "items": { "ipRanges": { "items": { "cidrIp": ["0.0.0.0/0"] } } }
      }
    }
  }
}
```
MITRE ATT&CK: T1562.007, Impair Defenses: Disable or Modify Cloud Firewall.

### Rule 3: S3 bucket exposure
An S3 bucket holds data and should stay private. This fires on any change to a bucket's public access settings or policy.

```json
{
  "source": ["aws.s3"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["s3.amazonaws.com"],
    "eventName": ["PutBucketPolicy", "PutBucketAcl", "DeleteBucketPublicAccessBlock", "PutBucketPublicAccessBlock"]
  }
}
```
MITRE ATT&CK: T1562.007 and T1530, Data from Cloud Storage.

## The simulated incident

With all three rules live, I played the attacker. I used a stolen-session scenario: an identity working from the AWS CLI instead of the console, running four destructive actions in under three minutes.

All times UTC (CloudTrail uses UTC, which matters for timeline work).

| Time (UTC) | Action | Event | Rule fired | Tactic |
|---|---|---|---|---|
| 04:45:36 | Removed S3 public access protection | DeleteBucketPublicAccessBlock | Rule 3 | Defense Evasion / Collection |
| 04:46:29 | Created a new security group (backdoor-sg) | CreateSecurityGroup | (none) | Persistence setup |
| 04:48:01 | Opened RDP (3389) to 0.0.0.0/0 | AuthorizeSecurityGroupIngress | Rule 2 | Persistence / Initial Access |
| 04:48:12 | Stopped CloudTrail logging | StopLogging | Rule 1 | Defense Evasion |

All three rules fired and I got three email alerts.

## Investigation

I switched to the analyst role and pulled the events in CloudTrail Event history, filtered to Read-only = false so I was only looking at changes, not read calls.

The key finding: the source IP was identical across setup, attack, and cleanup. If I had only alerted on a new or unusual IP, I would have caught nothing. What actually separated the attack from normal activity was:

1. **User agent.** The setup and containment work came from the console (a browser user agent). The four attack actions all came from `aws-cli/2.38.5 ... os/windows#11`. A sudden switch to direct CLI calls from a user who had been clicking in the console is a behavior change worth flagging.
2. **Velocity and sequence.** Four sensitive, state-changing actions in under three minutes (expose data, open a port, kill logging) is not what normal administration looks like.
3. **The order.** Stripping protections and then stopping logging last is a recognizable pattern: do the damage, then blind the defender.

Takeaway I'm keeping: one indicator is not enough. IP looked clean the whole time. The detection that mattered was correlating user agent, timing, and the sequence of actions.

## Containment

I restored visibility first, then closed the holes, which is the order I'd follow in a real incident.

| Time (UTC) | Action | Event |
|---|---|---|
| 04:55:10 | Re-enabled CloudTrail logging | StartLogging |
| 04:56:29 | Removed the RDP rule from backdoor-sg | RevokeSecurityGroupIngress |
| 04:57:11 | Re-enabled S3 block public access | PutBucketPublicAccessBlock |
| 04:59:34 | Deleted both test security groups | DeleteSecurityGroup |

## Tuning notes

`PutBucketPublicAccessBlock` fires whether someone is weakening protection (turning it off) or hardening it (turning it back on). So re-securing the bucket during containment triggered the same alert as the attack. That is a false positive: the rule can't tell hardening from weakening on its own.

In a real SOC I'd tune Rule 3 to inspect the request parameters and only fire when the public access settings are being set to false, so that remediation work doesn't generate noise.

## What I'd build next

- Tune the S3 rule to suppress hardening actions (above).
- Add detection for IAM changes (new users, new access keys, policy changes). Those are global events that only reach EventBridge in us-east-1, so this would mean a trail and rules in that region too.
- Route alerts to a Lambda that enriches them (geolocate the IP, flag off-hours activity) before they reach me.
- Auto-containment: a rule that, on StopLogging, automatically calls StartLogging and notifies, so logging can't stay off.

## Services used
CloudTrail, EventBridge, SNS, S3, EC2 (security groups), IAM, AWS CLI. Account secured with root MFA, a zero-spend budget, and a monthly spend limit.
