# Alert Formatting

By default, an EventBridge rule sends the full raw CloudTrail event (JSON) to its target. That is hard to read in an email at 1 AM, so each rule uses an SNS **input transformer** to pull out the fields that matter and send a single readable line instead.

An input transformer has two parts: an **input path** that maps variables to fields in the event, and a **template** that arranges those variables into the message.

## Rule 1: CloudTrail tampering

Input path:
```json
{
  "event": "$.detail.eventName",
  "user": "$.detail.userIdentity.arn",
  "ip": "$.detail.sourceIPAddress",
  "time": "$.detail.eventTime",
  "region": "$.detail.awsRegion",
  "trail": "$.detail.requestParameters.name"
}
```
Template:
```
"SECURITY ALERT: CloudTrail tampering. <user> called <event> on trail <trail> at <time> (UTC) from IP <ip> in <region>. Action: confirm the trail is logging and review this user's recent activity in CloudTrail Event history."
```

## Rule 2: Security group opened to the internet

Input path:
```json
{
  "event": "$.detail.eventName",
  "user": "$.detail.userIdentity.arn",
  "ip": "$.detail.sourceIPAddress",
  "time": "$.detail.eventTime",
  "sg": "$.detail.requestParameters.groupId"
}
```
Template:
```
"SECURITY ALERT: Security group opened to the internet. <user> called <event> on <sg> allowing 0.0.0.0/0 at <time> (UTC) from IP <ip>. Action: confirm this was approved, check which port was opened, and remove the rule if not needed."
```

## Rule 3: S3 bucket exposure

Input path:
```json
{
  "event": "$.detail.eventName",
  "user": "$.detail.userIdentity.arn",
  "ip": "$.detail.sourceIPAddress",
  "time": "$.detail.eventTime",
  "bucket": "$.detail.requestParameters.bucketName",
  "error": "$.detail.errorCode"
}
```
Template:
```
"SECURITY ALERT: S3 exposure change. <user> called <event> on bucket <bucket> at <time> (UTC) from IP <ip>. Error (blank means it succeeded): <error>. Action: verify the bucket's public access settings and confirm the change was approved."
```

## Example output

A raw StopLogging event became this one-line alert:

```
SECURITY ALERT: CloudTrail tampering. [role] called StopLogging on trail lab-trail at 2026-10-26T04:48:12Z (UTC) from IP [redacted] in us-east-2. Action: confirm the trail is logging and review this user's recent activity in CloudTrail Event history.
```
