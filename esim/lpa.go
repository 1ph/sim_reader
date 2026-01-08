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

func (l *LPA) DownloadProfile(smdpAddress, matchingID string) error {
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

	// 3. Initiate Authentication (ES9+)
	log.Println("Step 3: Initiating authentication with SM-DP+")
	initAuthResp, err := l.smdp.InitiateAuthentication(smdpAddress, challenge, info1)
	if err != nil {
		return fmt.Errorf("failed to initiate authentication: %w", err)
	}

	// Check for errors in response
	if initAuthResp["transactionId"] == nil {
		return fmt.Errorf("SM-DP+ returned error: %v", initAuthResp)
	}

	transactionID := initAuthResp["transactionId"].(string)
	serverSigned1B64 := initAuthResp["serverSigned1"].(string)
	serverSignature1B64 := initAuthResp["serverSignature1"].(string)
	euiccCiPKIdToBeUsedB64 := initAuthResp["euiccCiPKIdToBeUsed"].(string)
	serverCertificateB64 := initAuthResp["serverCertificate"].(string)

	// Decode from base64
	serverSigned1, _ := base64.StdEncoding.DecodeString(serverSigned1B64)
	serverSignature1, _ := base64.StdEncoding.DecodeString(serverSignature1B64)
	euiccCiPKIdToBeUsed, _ := base64.StdEncoding.DecodeString(euiccCiPKIdToBeUsedB64)
	serverCertificate, _ := base64.StdEncoding.DecodeString(serverCertificateB64)

	log.Printf("Building AuthenticateServerRequest:")
	log.Printf("  serverSigned1: %d bytes", len(serverSigned1))
	log.Printf("  serverSignature1: %d bytes", len(serverSignature1))
	log.Printf("  euiccCiPKIdToBeUsed: %d bytes", len(euiccCiPKIdToBeUsed))
	log.Printf("  serverCertificate: %d bytes", len(serverCertificate))

	// For now, just concatenate - we'll need to build proper ASN.1 later if this doesn't work
	authenticateServerRequest := make([]byte, 0)
	authenticateServerRequest = append(authenticateServerRequest, serverSigned1...)
	authenticateServerRequest = append(authenticateServerRequest, serverSignature1...)
	authenticateServerRequest = append(authenticateServerRequest, euiccCiPKIdToBeUsed...)
	authenticateServerRequest = append(authenticateServerRequest, serverCertificate...)

	log.Printf("Total AuthenticateServerRequest: %d bytes", len(authenticateServerRequest))

	// 4. Authenticate Server (ES10b)
	log.Println("Step 4: Authenticating server on eUICC")
	authenticateServerResponse, err := l.euicc.AuthenticateServer(authenticateServerRequest)
	if err != nil {
		return fmt.Errorf("failed to authenticate server on eUICC: %w", err)
	}

	// 5. Authenticate Client (ES9+)
	log.Println("Step 5: Authenticating client with SM-DP+")
	authClientResp, err := l.smdp.AuthenticateClient(transactionID, authenticateServerResponse)
	if err != nil {
		return fmt.Errorf("failed to authenticate client: %w", err)
	}

	// Build PrepareDownloadRequest from response
	profileMetadataB64 := authClientResp["profileMetadata"].(string)
	smdpSigned2B64 := authClientResp["smdpSigned2"].(string)
	smdpSignature2B64 := authClientResp["smdpSignature2"].(string)
	smdpCertificateB64 := authClientResp["smdpCertificate"].(string)

	profileMetadata, _ := base64.StdEncoding.DecodeString(profileMetadataB64)
	smdpSigned2, _ := base64.StdEncoding.DecodeString(smdpSigned2B64)
	smdpSignature2, _ := base64.StdEncoding.DecodeString(smdpSignature2B64)
	smdpCertificate, _ := base64.StdEncoding.DecodeString(smdpCertificateB64)

	prepareDownloadRequest := append(profileMetadata, smdpSigned2...)
	prepareDownloadRequest = append(prepareDownloadRequest, smdpSignature2...)
	prepareDownloadRequest = append(prepareDownloadRequest, smdpCertificate...)

	// 6. Prepare Download (ES10b)
	log.Println("Step 6: Preparing download on eUICC")
	prepareDownloadResponse, err := l.euicc.PrepareDownload(prepareDownloadRequest)
	if err != nil {
		return fmt.Errorf("failed to prepare download on eUICC: %w", err)
	}

	// 7. Get Bound Profile Package (ES9+)
	log.Println("Step 7: Getting Bound Profile Package (BPP) from SM-DP+")
	bppResp, err := l.smdp.GetBoundProfilePackage(transactionID, prepareDownloadResponse)
	if err != nil {
		return fmt.Errorf("failed to get BPP: %w", err)
	}

	bppB64 := bppResp["boundProfilePackage"].(string)
	bpp, _ := base64.StdEncoding.DecodeString(bppB64)

	// 8. Load Bound Profile Package (ES10b)
	log.Println("Step 8: Loading BPP onto eUICC (this may take a while)")
	err = l.euicc.LoadBoundProfilePackage(bpp)
	if err != nil {
		return fmt.Errorf("failed to load BPP onto eUICC: %w", err)
	}

	log.Println("Profile successfully installed!")
	return nil
}

func (l *LPA) DownloadProfileToFile(smdpAddress, matchingID string, filename string) error {
	log.Println("Starting profile download to file...")

	challenge, err := l.euicc.GetEuiccChallenge()
	if err != nil {
		return err
	}
	info1, err := l.euicc.GetEuiccInfo1()
	if err != nil {
		return err
	}
	
	initAuthResp, err := l.smdp.InitiateAuthentication(smdpAddress, challenge, info1)
	if err != nil {
		return err
	}

	if initAuthResp["transactionId"] == nil {
		return fmt.Errorf("SM-DP+ returned error: %v", initAuthResp)
	}

	transactionID := initAuthResp["transactionId"].(string)
	serverSigned1B64 := initAuthResp["serverSigned1"].(string)
	serverSignature1B64 := initAuthResp["serverSignature1"].(string)
	euiccCiPKIdToBeUsedB64 := initAuthResp["euiccCiPKIdToBeUsed"].(string)
	serverCertificateB64 := initAuthResp["serverCertificate"].(string)

	serverSigned1, _ := base64.StdEncoding.DecodeString(serverSigned1B64)
	serverSignature1, _ := base64.StdEncoding.DecodeString(serverSignature1B64)
	euiccCiPKIdToBeUsed, _ := base64.StdEncoding.DecodeString(euiccCiPKIdToBeUsedB64)
	serverCertificate, _ := base64.StdEncoding.DecodeString(serverCertificateB64)

	authenticateServerRequest := append(serverSigned1, serverSignature1...)
	authenticateServerRequest = append(authenticateServerRequest, euiccCiPKIdToBeUsed...)
	authenticateServerRequest = append(authenticateServerRequest, serverCertificate...)

	authenticateServerResponse, err := l.euicc.AuthenticateServer(authenticateServerRequest)
	if err != nil {
		return err
	}

	authClientResp, err := l.smdp.AuthenticateClient(transactionID, authenticateServerResponse)
	if err != nil {
		return err
	}

	profileMetadataB64 := authClientResp["profileMetadata"].(string)
	smdpSigned2B64 := authClientResp["smdpSigned2"].(string)
	smdpSignature2B64 := authClientResp["smdpSignature2"].(string)
	smdpCertificateB64 := authClientResp["smdpCertificate"].(string)

	profileMetadata, _ := base64.StdEncoding.DecodeString(profileMetadataB64)
	smdpSigned2, _ := base64.StdEncoding.DecodeString(smdpSigned2B64)
	smdpSignature2, _ := base64.StdEncoding.DecodeString(smdpSignature2B64)
	smdpCertificate, _ := base64.StdEncoding.DecodeString(smdpCertificateB64)

	prepareDownloadRequest := append(profileMetadata, smdpSigned2...)
	prepareDownloadRequest = append(prepareDownloadRequest, smdpSignature2...)
	prepareDownloadRequest = append(prepareDownloadRequest, smdpCertificate...)

	prepareDownloadResponse, err := l.euicc.PrepareDownload(prepareDownloadRequest)
	if err != nil {
		return err
	}

	bppResp, err := l.smdp.GetBoundProfilePackage(transactionID, prepareDownloadResponse)
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

