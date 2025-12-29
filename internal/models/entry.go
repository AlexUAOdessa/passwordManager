package models

type Entry struct {
	Service  string `json:"s"`
	Login    string `json:"l"`
	Password string `json:"p"`
}

type Vault struct {
	Entries []Entry
}