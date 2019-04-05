package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

// ContentSecurityPolicyReportParent is the overall CSP report that we receive
type ContentSecurityPolicyReportParent struct {
	Report ContentSecurityPolicyReport `json:"csp-report"`
}

// ContentSecurityPolicyReport is the innards of the CSP report that we actully care about
type ContentSecurityPolicyReport struct {
	BlockedURI         string `json:"blocked-uri"`
	ColumnNumber       int64  `json:"column-number,omitempty"`
	Disposition        string `json:"disposition,omitempty"`
	DocumentURI        string `json:"document-uri"`
	EffectiveDirective string `json:"effective-directive"`
	LineNumber         int64  `json:"line-number,omitempty"`
	OriginalPolicy     string `json:"original-policy"`
	Referrer           string `json:"referrer"`
	ScriptSample       string `json:"script-sample,omitempty"`
	SourceFile         string `json:"source-file,omitempty"`
	StatusCode         int    `json:"status-code"`
	ViolatedDirective  string `json:"violated-directive"`
}

// HandleRequest is the AWS lambda handler function
func HandleRequest(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var reportForwarded = false
	var report ContentSecurityPolicyReportParent

	err := json.Unmarshal([]byte(request.Body), &report)

	if err != nil {
		return events.APIGatewayProxyResponse{
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       fmt.Sprintf("{\"report_forwarded\": %s, \"error_message\": \"Error unmarshalling CSP report JSON to Struct\"}", strconv.FormatBool(reportForwarded)),
			StatusCode: 400,
		}, nil
	}

	if reportShouldBeForwarded(report.Report) {
		var uri = "https://sentry.io/api/1377947/security/?sentry_key=f7898bf4858d436aa3568ae042371b94"

		reportString, err := json.Marshal(report)

		if err != nil {
			return events.APIGatewayProxyResponse{
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       fmt.Sprintf("{\"report_forwarded\": %s, \"error_message\": \"Error marshalling CSP report JSON to String\"}", strconv.FormatBool(reportForwarded)),
				StatusCode: 400,
			}, nil
		}

		client := &http.Client{}
		req, _ := http.NewRequest("POST", uri, bytes.NewBuffer(reportString))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", request.Headers["User-Agent"])
		req.Header.Set("X-Forwarder-User-Agent", "GOV.UK CSP Fowarder")
		resp, err := client.Do(req)

		// Sentry returns a 201 Created code if the report is successful
		if resp.StatusCode != 201 || err != nil {
			body, _ := ioutil.ReadAll(resp.Body)

			return events.APIGatewayProxyResponse{
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       fmt.Sprintf("{\"report_forwarded\": %s, \"error_message\": \"Error sending CSP report to Sentry\", \"sentry_error_message\": %s, \"sentry_status_code\": %d, \"csp_report_sent_to_sentry\": %s}", strconv.FormatBool(reportForwarded), body, resp.StatusCode, reportString),
				StatusCode: 502,
			}, nil
		}

		reportForwarded = true
	}

	return events.APIGatewayProxyResponse{
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       fmt.Sprintf("{\"report_forwarded\": %s}", strconv.FormatBool(reportForwarded)),
		StatusCode: 200,
	}, nil
}

func reportShouldBeForwarded(report ContentSecurityPolicyReport) bool {
	// Ignore all schemes except HTTPS and HTTP
	schemeSafelist := map[string]bool{
		"https": true,
		"http":  true,
	}

	// Ignore host names that are not real host names
	fakeHostnameBlocklist := map[string]bool{
		"about":  true,
		"blob":   true,
		"eval":   true,
		"inline": true,
	}

	// Ignore host names for known browser extensions
	hostnameBlocklist := map[string]bool{
		"www.gstatic.com":                true,
		"data1.klastaf.com":              true,
		"data1.pictdog.com":              true,
		"cardinaldata.net":               true,
		"promclickapp.biz":               true,
		"gateway.zscalertwo.net":         true,
		"lowffdompro.com":                true,
		"data1.biilut.com":               true,
		"data1.bmi-result.com":           true,
		"mstat.acestream.net":            true,
		"mc.yandex.ru":                   true,
		"block.opendns.com":              true,
		"skytraf.xyz":                    true,
		"colextidapp.com":                true,
		"mozbar.moz.com":                 true,
		"gjtrack.ucweb.com":              true,
		"data1.plicifa.com":              true,
		"data1.gribul.com":               true,
		"data1.my-drivingdirections.com": true,
		"data1.myloap.com":               true,
		"api.microsofttranslator.com":    true,
		"ssl.microsofttranslator.com":    true,
	}

	uri, err := url.Parse(report.BlockedURI)

	if err != nil {
		return false
	}

	if report.BlockedURI != "" && schemeSafelist[uri.Scheme] &&
		!fakeHostnameBlocklist[report.BlockedURI] && !hostnameBlocklist[uri.Host] {
		return true
	}

	return false
}

func main() {
	lambda.Start(HandleRequest)
}
