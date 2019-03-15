package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/aws/aws-lambda-go/lambda"
)

// ContentSecurityPolicyReportParent is the overall CSP report that we receive
type ContentSecurityPolicyReportParent struct {
	Report ContentSecurityPolicyReport `json:"csp-report"`
}

// ContentSecurityPolicyReport is the innards of the CSP report that we actully care about
type ContentSecurityPolicyReport struct {
	BlockedURI         string `json:"blocked-uri"`
	Disposition        string `json:"disposition"`
	DocumentURI        string `json:"document-uri"`
	EffectiveDirective string `json:"effective-directive"`
	OriginalPolicy     string `json:"original-policy"`
	Referrer           string `json:"referrer"`
	ScriptSample       string `json:"script-sample"`
	StatusCode         string `json:"status-code"`
	ViolatedDirective  string `json:"violated-directive"`
}

// HandleRequest is the AWS lambda handler function
func HandleRequest(ctx context.Context, report ContentSecurityPolicyReportParent) (string, error) {
	var reportForwarded = false

	if reportShouldBeForwarded(report.Report) {
		var uri = "https://sentry.io/api/1377947/security/?sentry_key=f7898bf4858d436aa3568ae042371b94"

		reportString, err := json.Marshal(report)

		if err != nil {
			return "", fmt.Errorf("{\"report_forwarded\": %s, \"error_message\": \"Error marshalling CSP report JSON to String\"}", strconv.FormatBool(reportForwarded))
		}

		resp, err := http.Post(uri, "application/json", bytes.NewBuffer(reportString))

		if resp.StatusCode != 200 || err != nil {
			return "", fmt.Errorf("{\"report_forwarded\": %s, \"error_message\": \"Error sending CSP report to Sentry\"}", strconv.FormatBool(reportForwarded))
		}

		reportForwarded = true
	}

	return fmt.Sprintf("{\"report_forwarded\": %s}", strconv.FormatBool(reportForwarded)), nil
}

func reportShouldBeForwarded(report ContentSecurityPolicyReport) bool {
	// Ignore all schemes except HTTPS
	schemeSafelist := map[string]bool{"https": true}

	// Ignore host names for known browser extensions
	hostnameBlocklist := map[string]bool{
		"data1.klastaf.com":      true,
		"data1.pictdog.com":      true,
		"cardinaldata.net":       true,
		"promclickapp.biz":       true,
		"gateway.zscalertwo.net": true,
		"lowffdompro.com":        true,
		"data1.biilut.com":       true,
		"data1.bmi-result.com":   true,
		"mstat.acestream.net":    true,
		"mc.yandex.ru":           true,
		"block.opendns.com":      true,
	}

	uri, err := url.Parse(report.BlockedURI)

	if err != nil {
		return false
	}

	if schemeSafelist[uri.Scheme] && !hostnameBlocklist[uri.Host] {
		return true
	}

	return false
}

func main() {
	lambda.Start(HandleRequest)
}
