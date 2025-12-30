package models

type Entry struct {
	Service   string `json:"service"`
	Login     string `json:"login"`
	Password  string `json:"password"`
	Group     string `json:"group"`      // Название группы
	IsDeleted bool   `json:"is_deleted"` // Флаг корзины
}