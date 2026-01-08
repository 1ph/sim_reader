package esim

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

type SMDPClient struct {
	URL        string
	HTTPClient *http.Client
}

func NewSMDPClient(smdpURL string, insecure bool) *SMDPClient {
	client := &http.Client{}
	
	if insecure {
		// Skip TLS certificate verification for testing
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	
	return &SMDPClient{
		URL:        smdpURL,
		HTTPClient: client,
	}
}

type CommonResponse struct {
	Header struct {
		FunctionExecutionStatus struct {
			Status string `json:"status"`
		} `json:"functionExecutionStatus"`
	} `json:"header"`
}

func (s *SMDPClient) post(api string, request interface{}, response interface{}) error {
	url := fmt.Sprintf("%s/gsma/rsp2/es9plus/%s", s.URL, api)
	
	jsonData, err := json.Marshal(request)
	if err != nil {
		return err
	}
	
	log.Printf("SM-DP+ >> POST %s", url)
	log.Printf("SM-DP+ >> Request: %s", string(jsonData))
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	
	req.Header.Set("User-Agent", "gsma-rsp-lpad")
	req.Header.Set("X-Admin-Protocol", "gsma/rsp/v2.2.2")
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	
	log.Printf("SM-DP+ << Status: %d %s", resp.StatusCode, resp.Status)
	log.Printf("SM-DP+ << Response: %s", string(body))
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP error: %d %s", resp.StatusCode, resp.Status)
	}
	
	err = json.Unmarshal(body, response)
	if err != nil {
		return err
	}
	
	// Check for SM-DP+ errors in response
	if respMap, ok := response.(*map[string]interface{}); ok {
		if header, ok := (*respMap)["header"].(map[string]interface{}); ok {
			if fes, ok := header["functionExecutionStatus"].(map[string]interface{}); ok {
				if status, ok := fes["status"].(string); ok && status != "Executed-Success" {
					// Extract error details
					msg := "Unknown error"
					if scd, ok := fes["statusCodeData"].(map[string]interface{}); ok {
						if m, ok := scd["message"].(string); ok {
							msg = m
						}
					}
					return fmt.Errorf("SM-DP+ error: %s", msg)
				}
			}
		}
	}
	
	return nil
}

func (s *SMDPClient) InitiateAuthentication(smdpAddress string, challenge []byte, info1 []byte) (map[string]interface{}, error) {
	req := map[string]interface{}{
		"header":         map[string]interface{}{},
		"smdpAddress":    smdpAddress,
		"euiccChallenge": base64.StdEncoding.EncodeToString(challenge),
		"euiccInfo1":     base64.StdEncoding.EncodeToString(info1),
	}
	
	var resp map[string]interface{}
	err := s.post("initiateAuthentication", req, &resp)
	return resp, err
}

func (s *SMDPClient) AuthenticateClient(transactionID string, authenticateServerResponse []byte) (map[string]interface{}, error) {
	req := map[string]interface{}{
		"header":                      map[string]interface{}{},
		"transactionId":               transactionID,
		"authenticateServerResponse": base64.StdEncoding.EncodeToString(authenticateServerResponse),
	}
	
	var resp map[string]interface{}
	err := s.post("authenticateClient", req, &resp)
	return resp, err
}

func (s *SMDPClient) GetBoundProfilePackage(transactionID string, prepareDownloadResponse []byte) (map[string]interface{}, error) {
	req := map[string]interface{}{
		"header": map[string]interface{}{},
		"transactionId": transactionID,
		"prepareDownloadResponse": base64.StdEncoding.EncodeToString(prepareDownloadResponse),
	}
	
	var resp map[string]interface{}
	err := s.post("getBoundProfilePackage", req, &resp)
	return resp, err
}

func (s *SMDPClient) CancelSession(transactionID string, reason byte) error {
	req := map[string]interface{}{
		"header": map[string]interface{}{},
		"transactionId": transactionID,
		"reason": reason,
	}
	
	var resp CommonResponse
	return s.post("cancelSession", req, &resp)
}

