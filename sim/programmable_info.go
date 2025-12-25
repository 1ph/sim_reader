package sim

import (
	"sim_reader/card"
)

// GetProgrammableCardTypeName returns human-readable name for card type
func GetProgrammableCardTypeName(cardType card.ProgrammableCardType) string {
	switch cardType {
	case card.CardTypeGRv2:
		return "Grcard v2 / open5gs (GRv2)"
	case card.CardTypeGRv1:
		return "Grcard v1 (GRv1)"
	case card.CardTypeSysmocom:
		return "sysmocom sysmoUSIM-GR1"
	default:
		return "Unknown"
	}
}

// ShowProgrammableCardInfo displays information about the programmable card
// This function is called from main.go which uses output package to display
func ShowProgrammableCardInfo(reader *card.Reader) string {
	cardType := card.DetectProgrammableCardType(reader.ATR())
	return GetProgrammableCardTypeName(cardType)
}
