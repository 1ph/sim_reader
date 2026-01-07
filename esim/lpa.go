package esim

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
)

type LPA struct {
	euicc *EUICC
	smdp  *SMDPClient
}

func NewLPA(euicc *EUICC, smdp *SMDPClient) *LPA {
	return &LPA{
		euicc: euicc,
		smdp:  smdp,
	}
}

func (l *LPA) DownloadProfile(matchingID string) error {
	log.Println("Starting profile download...")

	// 1. Get EUICC Challenge
	log.Println("Step 1: Getting eUICC Challenge")
	challenge, err := l.euicc.GetEuiccChallenge()
	if err != nil {
		return fmt.Errorf("failed to get eUICC challenge: %w", err)
	}
	log.Printf("Challenge: %X\n", challenge)

	// 2. Get EUICC Info1
	log.Println("Step 2: Getting eUICC Info1")
	info1, err := l.euicc.GetEuiccInfo1()
	if err != nil {
		return fmt.Errorf("failed to get eUICC info1: %w", err)
	}

	// 3. Authenticate Client (ES9+)
	log.Println("Step 3: Authenticating client with SM-DP+")
	authClientResp, err := l.smdp.AuthenticateClient(matchingID, challenge, info1)
	if err != nil {
		return fmt.Errorf("failed to authenticate client: %w", err)
	}

	transactionID := authClientResp["transactionId"].(string)
	serverAuthRespB64 := authClientResp["authenticateServerResponse"].(string)
	serverAuthResp, _ := base64.StdEncoding.DecodeString(serverAuthRespB64)

	// 4. Authenticate Server (ES10b)
	log.Println("Step 4: Authenticating server on eUICC")
	prepDownloadResp, err := l.euicc.AuthenticateServer(serverAuthResp)
	if err != nil {
		return fmt.Errorf("failed to authenticate server on eUICC: %w", err)
	}

	// 5. Get Bound Profile Package (ES9+)
	log.Println("Step 5: Getting Bound Profile Package (BPP) from SM-DP+")
	bppResp, err := l.smdp.GetBoundProfilePackage(transactionID, prepDownloadResp)
	if err != nil {
		return fmt.Errorf("failed to get BPP: %w", err)
	}

	bppB64 := bppResp["boundProfilePackage"].(string)
	bpp, _ := base64.StdEncoding.DecodeString(bppB64)

	// 6. Load Bound Profile Package (ES10b)
	log.Println("Step 6: Loading BPP onto eUICC (this may take a while)")
	err = l.euicc.LoadBoundProfilePackage(bpp)
	if err != nil {
		return fmt.Errorf("failed to load BPP onto eUICC: %w", err)
	}

	log.Println("Profile successfully installed!")
	return nil
}

func (l *LPA) DownloadProfileToFile(matchingID string, filename string) error {
	log.Println("Starting profile download to file...")

	challenge, err := l.euicc.GetEuiccChallenge()
	if err != nil {
		return err
	}
	info1, err := l.euicc.GetEuiccInfo1()
	if err != nil {
		return err
	}
	authClientResp, err := l.smdp.AuthenticateClient(matchingID, challenge, info1)
	if err != nil {
		return err
	}

	transactionID := authClientResp["transactionId"].(string)
	serverAuthRespB64 := authClientResp["authenticateServerResponse"].(string)
	serverAuthResp, _ := base64.StdEncoding.DecodeString(serverAuthRespB64)

	prepDownloadResp, err := l.euicc.AuthenticateServer(serverAuthResp)
	if err != nil {
		return err
	}

	bppResp, err := l.smdp.GetBoundProfilePackage(transactionID, prepDownloadResp)
	if err != nil {
		return err
	}

	bppB64 := bppResp["boundProfilePackage"].(string)
	bpp, _ := base64.StdEncoding.DecodeString(bppB64)

	err = os.WriteFile(filename, bpp, 0644)
	if err != nil {
		return fmt.Errorf("failed to save BPP to file: %w", err)
	}

	log.Printf("Profile BPP saved to %s\n", filename)
	return nil
}

func (l *LPA) InstallProfileFromFile(filename string) error {
	log.Printf("Installing profile from file: %s\n", filename)
	bpp, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read BPP file: %w", err)
	}

	err = l.euicc.LoadBoundProfilePackage(bpp)
	if err != nil {
		return fmt.Errorf("failed to load BPP onto eUICC: %w", err)
	}

	log.Println("Profile successfully installed from file!")
	return nil
}

