package circuit

type CircuitEnum int

const (
	RlpHash CircuitEnum = iota
	NoSigRlp
	ToG2Hash
	NeoxOuter
	N3Verifier
	Invalid
)

func (ce CircuitEnum) IsNeox() bool {
	switch ce {
	case RlpHash, NoSigRlp, ToG2Hash, NeoxOuter:
		return true
	default:
		return false
	}
}
func (ce CircuitEnum) IsInvalid() bool {
	return ce == Invalid
}

type HashableBlockHeader interface {
	Encode(...any) ([]byte, error) // has sig
	Hash(...any) ([]byte, error)
	UnmarshalJSON([]byte) error
	MarshalJSON() ([]byte, error)
}
