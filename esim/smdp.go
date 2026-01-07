package esim

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type SMDPClient struct {
	URL        string
	HTTPClient *http.Client
}

func NewSMDPClient(smdpURL string) *SMDPClient {
	return &SMDPClient{
		URL:        smdpURL,
		HTTPClient: &http.Client{},
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
	url := fmt.Sprintf("https://%s/gsma/rsp2/es9plus/%s", s.URL, api)
	
	jsonData, err := json.Marshal(request)
	if err != nil {
		return err
	}
	
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
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP error: %d %s", resp.StatusCode, resp.Status)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	
	return json.Unmarshal(body, response)
}

func (s *SMDPClient) AuthenticateClient(matchingID string, challenge []byte, info1 []byte) (map[string]interface{}, error) {
	req := map[string]interface{}{
		"header": map[string]interface{}{},
		"matchingId": matchingID,
		"euiccChallenge": base64.StdEncoding.EncodeToString(challenge),
		"euiccInfo1": base64.StdEncoding.EncodeToString(info1),
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

