// Package card provides PC/SC smart card reader functionality
package card

import (
	"fmt"

	"github.com/ebfe/scard"
)

// Reader represents a smart card reader connection
type Reader struct {
	ctx  *scard.Context
	card *scard.Card
	name string
	atr  []byte
}

// ListReaders returns a list of available smart card readers
func ListReaders() ([]string, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, fmt.Errorf("failed to establish PC/SC context: %w", err)
	}
	defer ctx.Release()

	readers, err := ctx.ListReaders()
	if err != nil {
		return nil, fmt.Errorf("failed to list readers: %w", err)
	}

	return readers, nil
}

// Connect connects to a smart card reader by index
func Connect(readerIndex int) (*Reader, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, fmt.Errorf("failed to establish PC/SC context: %w", err)
	}

	readers, err := ctx.ListReaders()
	if err != nil {
		ctx.Release()
		return nil, fmt.Errorf("failed to list readers: %w", err)
	}

	if len(readers) == 0 {
		ctx.Release()
		return nil, fmt.Errorf("no smart card readers found")
	}

	if readerIndex < 0 || readerIndex >= len(readers) {
		ctx.Release()
		return nil, fmt.Errorf("reader index %d out of range (0-%d)", readerIndex, len(readers)-1)
	}

	readerName := readers[readerIndex]

	card, err := ctx.Connect(readerName, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		ctx.Release()
		return nil, fmt.Errorf("failed to connect to card in reader '%s': %w", readerName, err)
	}

	status, err := card.Status()
	if err != nil {
		card.Disconnect(scard.LeaveCard)
		ctx.Release()
		return nil, fmt.Errorf("failed to get card status: %w", err)
	}

	return &Reader{
		ctx:  ctx,
		card: card,
		name: readerName,
		atr:  status.Atr,
	}, nil
}

// ConnectFirst connects to the first available reader with a card
func ConnectFirst() (*Reader, error) {
	return Connect(0)
}

// Transmit sends an APDU command to the card and returns the response
func (r *Reader) Transmit(apdu []byte) ([]byte, error) {
	response, err := r.card.Transmit(apdu)
	if err != nil {
		return nil, fmt.Errorf("transmit failed: %w", err)
	}
	return response, nil
}

// Close closes the connection to the card and releases resources
func (r *Reader) Close() error {
	if r.card != nil {
		r.card.Disconnect(scard.LeaveCard)
	}
	if r.ctx != nil {
		r.ctx.Release()
	}
	return nil
}

// Name returns the reader name
func (r *Reader) Name() string {
	return r.name
}

// ATR returns the Answer To Reset bytes
func (r *Reader) ATR() []byte {
	return r.atr
}

// ATRHex returns the ATR as hex string
func (r *Reader) ATRHex() string {
	return fmt.Sprintf("%X", r.atr)
}

// Reconnect performs a card reset/reconnection
// If cold is true, performs a cold reset (power cycle)
func (r *Reader) Reconnect(cold bool) error {
	if r.card == nil {
		return fmt.Errorf("no card connected")
	}

	var initType scard.Disposition
	if cold {
		initType = scard.UnpowerCard // Cold reset - power off the card
	} else {
		initType = scard.ResetCard // Warm reset
	}

	err := r.card.Reconnect(scard.ShareShared, scard.ProtocolAny, initType)
	if err != nil {
		return fmt.Errorf("reconnect failed: %w", err)
	}

	// Update ATR
	status, err := r.card.Status()
	if err == nil {
		r.atr = status.Atr
	}

	return nil
}
