# GOV.UK CSP Forwarder

A Go-based Lamdba function to receive, filter and forward CSP reports to Sentry.

This Lambda function runs in AWS and pre-filters out most of the CSP junk reports that are generated as a result of browser extensions injecting scripts into GOV.UK pages. The rest of the reports are forwarded to Sentry where they are logged and triaged.

## Releasing

The [Jenkinsfile](Jenkinsfile) builds an executable artefact on each run and uploads this to AWS S3. This artefact is then deployed to AWS Lambda using [Terraform](https://github.com/alphagov/govuk-aws). The Lambda lives in the `govuk-tools` AWS account.

## Licence

[MIT License](LICENCE)
