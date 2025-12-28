package testing

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"time"
)

// Report represents the full test report
type Report struct {
	Timestamp   time.Time     `json:"timestamp"`
	CardATR     string        `json:"card_atr,omitempty"`
	CardICCID   string        `json:"card_iccid,omitempty"`
	Summary     TestSummary   `json:"summary"`
	Results     []TestResult  `json:"results"`
}

// GenerateReport generates both JSON and HTML reports
func (s *TestSuite) GenerateReport(prefix string) error {
	report := Report{
		Timestamp: time.Now(),
		Summary:   s.GetSummary(),
		Results:   s.Results,
	}
	
	// Get ATR if reader available
	if s.Reader != nil {
		report.CardATR = s.Reader.ATRHex()
	}
	
	// Generate JSON
	jsonPath := prefix + ".json"
	if err := s.generateJSON(jsonPath, report); err != nil {
		return fmt.Errorf("JSON generation failed: %w", err)
	}
	fmt.Printf("✓ JSON report: %s\n", jsonPath)
	
	// Generate HTML
	htmlPath := prefix + ".html"
	if err := s.generateHTML(htmlPath, report); err != nil {
		return fmt.Errorf("HTML generation failed: %w", err)
	}
	fmt.Printf("✓ HTML report: %s\n", htmlPath)
	
	return nil
}

func (s *TestSuite) generateJSON(path string, report Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (s *TestSuite) generateHTML(path string, report Report) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"statusClass": func(passed bool) string {
			if passed {
				return "pass"
			}
			return "fail"
		},
		"statusIcon": func(passed bool) string {
			if passed {
				return "✓"
			}
			return "✗"
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	
	return tmpl.Execute(f, report)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SIM Card Test Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e; color: #eee; padding: 20px; line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #00d4ff; margin-bottom: 20px; }
        h2 { color: #ff6b6b; margin: 20px 0 10px; border-bottom: 1px solid #333; padding-bottom: 5px; }
        .summary { 
            display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); 
            gap: 15px; margin-bottom: 30px;
        }
        .stat { 
            background: #16213e; padding: 20px; border-radius: 8px; text-align: center;
        }
        .stat-value { font-size: 2em; font-weight: bold; }
        .stat-label { color: #888; font-size: 0.9em; }
        .pass .stat-value { color: #4ade80; }
        .fail .stat-value { color: #f87171; }
        .rate .stat-value { color: #fbbf24; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #16213e; color: #00d4ff; }
        tr:hover { background: #1f2937; }
        .status-pass { color: #4ade80; }
        .status-fail { color: #f87171; }
        .apdu { font-family: monospace; font-size: 0.85em; color: #a5b4fc; }
        .error { color: #f87171; font-size: 0.9em; }
        .spec { color: #888; font-size: 0.85em; }
        details { margin: 10px 0; }
        summary { cursor: pointer; padding: 10px; background: #16213e; border-radius: 5px; }
        summary:hover { background: #1f2937; }
        .meta { color: #888; font-size: 0.9em; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 SIM Card Test Report</h1>
        
        <div class="meta">
            <p>Generated: {{.Timestamp.Format "2006-01-02 15:04:05"}}</p>
            {{if .CardATR}}<p>ATR: <span class="apdu">{{.CardATR}}</span></p>{{end}}
            {{if .CardICCID}}<p>ICCID: {{.CardICCID}}</p>{{end}}
        </div>
        
        <div class="summary">
            <div class="stat">
                <div class="stat-value">{{.Summary.Total}}</div>
                <div class="stat-label">Total Tests</div>
            </div>
            <div class="stat pass">
                <div class="stat-value">{{.Summary.Passed}}</div>
                <div class="stat-label">Passed</div>
            </div>
            <div class="stat fail">
                <div class="stat-value">{{.Summary.Failed}}</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat rate">
                <div class="stat-value">{{printf "%.1f" .Summary.PassRate}}%</div>
                <div class="stat-label">Pass Rate</div>
            </div>
        </div>
        
        {{if .Summary.FailedTests}}
        <h2>❌ Failed Tests</h2>
        <ul>
            {{range .Summary.FailedTests}}
            <li class="status-fail">{{.}}</li>
            {{end}}
        </ul>
        {{end}}
        
        <h2>📋 All Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Category</th>
                    <th>Test Name</th>
                    <th>Result</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {{range .Results}}
                <tr>
                    <td class="status-{{statusClass .Passed}}">{{statusIcon .Passed}}</td>
                    <td>{{.Category}}</td>
                    <td>{{.Name}}</td>
                    <td>{{.Actual}}</td>
                    <td>
                        {{if .APDU}}<span class="apdu">APDU: {{.APDU}}</span><br>{{end}}
                        {{if .Error}}<span class="error">{{.Error}}</span><br>{{end}}
                        {{if .Spec}}<span class="spec">{{.Spec}}</span>{{end}}
                    </td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
</body>
</html>`

