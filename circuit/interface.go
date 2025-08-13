package circuit

type HashableBlockHeader interface {
	Encode(...any) ([]byte, error) // has sig
	Hash(...any) ([]byte, error)
	UnmarshalJSON([]byte) error
	MarshalJSON() ([]byte, error)
}
